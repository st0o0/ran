package trap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	// pjlMaxChunk bounds one read unit: a line, or 1024 bytes of binary data.
	pjlMaxChunk = 1024
	// pjlMaxTotal bounds the bytes read per session.
	pjlMaxTotal = 64 << 10
	// pjlMaxEvents bounds the PJL commands and print data runs served per session.
	pjlMaxEvents = 64
	// pjlSampleBytes is the printable prefix of a print data run that is logged.
	pjlSampleBytes = 64
	// pjlHashHexLen is the number of hex characters kept from the data hash.
	pjlHashHexLen = 16

	pjlKindInfo      = "info"
	pjlKindFS        = "fs_command"
	pjlKindPrintData = "print_data"
	pjlKindSet       = "set"
	pjlKindJob       = "job"
	pjlKindOther     = "other"
)

// pjlUEL is the Universal Exit Language sequence that frames PJL jobs.
var pjlUEL = []byte("\x1b%-12345X")

// Fixed printer identity. The model is a plausible product name, the serial
// number is invented.
const (
	pjlModel  = "HP LaserJet M605dn"
	pjlSerial = "CNRAN00001"
)

// PJLTrap is a stub of a JetDirect printer (TCP 9100). PJL information queries
// get a fixed printer identity; filesystem and setting commands are commands and
// refused; anything else (PCL, PostScript) is counted as print data and only
// summarized by length, hash and a short printable prefix.
type PJLTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewPJL(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *PJLTrap {
	t := &PJLTrap{cfg: cfg, logger: logger, metrics: m}
	t.tcpServer = newTCPServer("pjl", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

// pjlCommand is a classified PJL command. verb and what come from fixed lists,
// never from client text.
type pjlCommand struct {
	kind string
	verb string
	what string
}

var pjlFSVerbs = map[string]bool{
	"FSDIR": true, "FSUPLOAD": true, "FSDOWNLOAD": true, "FSDELETE": true,
	"FSMKDIR": true, "FSQUERY": true, "FSAPPEND": true, "FSINIT": true, "FSCOPY": true,
}

var pjlSetVerbs = map[string]bool{
	"SET": true, "DEFAULT": true, "INITIALIZE": true, "RESET": true,
	"OPMSG": true, "STMSG": true, "DMCMD": true, "DMINFO": true, "EXECUTE": true,
}

var pjlJobVerbs = map[string]bool{
	"JOB": true, "EOJ": true, "ENTER": true, "COMMENT": true, "ECHO": true,
	"USTATUS": true, "USTATUSOFF": true, "INQUIRE": true, "DINQUIRE": true,
}

var pjlInfoCategories = map[string]bool{
	"ID": true, "STATUS": true, "CONFIG": true, "VARIABLES": true, "USTATUS": true,
	"MEMORY": true, "FILESYS": true, "PAGECOUNT": true,
}

// classifyPJL classifies one line. ok is false when the line is not a PJL
// command (it is print data).
func classifyPJL(line string) (cmd pjlCommand, ok bool) {
	f := strings.Fields(line)
	if len(f) < 1 || !strings.EqualFold(f[0], "@PJL") {
		return cmd, false
	}
	if len(f) == 1 {
		// A bare "@PJL" is a no-op in the protocol.
		return pjlCommand{kind: pjlKindJob, verb: "NOP"}, true
	}
	verb := strings.ToUpper(f[1])
	switch {
	case verb == "INFO":
		what := ""
		if len(f) >= 3 {
			what = strings.ToUpper(f[2])
		}
		if !pjlInfoCategories[what] {
			what = ""
		}
		return pjlCommand{kind: pjlKindInfo, verb: verb, what: what}, true
	case pjlFSVerbs[verb]:
		return pjlCommand{kind: pjlKindFS, verb: verb}, true
	case pjlSetVerbs[verb]:
		return pjlCommand{kind: pjlKindSet, verb: verb}, true
	case pjlJobVerbs[verb]:
		return pjlCommand{kind: pjlKindJob, verb: verb}, true
	default:
		return pjlCommand{kind: pjlKindOther, verb: "UNKNOWN"}, true
	}
}

// pjlAttack reports whether a command kind makes the session an attack.
func pjlAttack(kind string) bool {
	return kind == pjlKindFS || kind == pjlKindSet || kind == pjlKindOther
}

const pjlFF = "\r\n\f"

// pjlResponse builds the fixed answer to a command. Nothing in it comes from the
// request.
func pjlResponse(c pjlCommand) string {
	switch c.kind {
	case pjlKindInfo:
		switch c.what {
		case "ID":
			return "@PJL INFO ID\r\n\"" + pjlModel + "\"" + pjlFF
		case "STATUS":
			return "@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE" + pjlFF
		case "CONFIG":
			return "@PJL INFO CONFIG\r\nMODEL=\"" + pjlModel + "\"\r\nSERIAL NUMBER=\"" + pjlSerial + "\"\r\nMEMORY=268435456\r\nDUPLEX\r\nPAGE COUNT=1337" + pjlFF
		case "VARIABLES":
			return "@PJL INFO VARIABLES\r\nCOPIES=1 [1 RANGE]\r\n\t1 - 999\r\nPAPER=LETTER [3 ENUMERATED]\r\n\tLETTER\r\n\tLEGAL\r\n\tA4\r\nORIENTATION=PORTRAIT [2 ENUMERATED]\r\n\tPORTRAIT\r\n\tLANDSCAPE" + pjlFF
		case "USTATUS":
			return "@PJL USTATUS DEVICE\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE" + pjlFF
		case "PAGECOUNT":
			return "@PJL INFO PAGECOUNT\r\n1337" + pjlFF
		case "MEMORY":
			return "@PJL INFO MEMORY\r\nTOTAL=268435456\r\nLARGEST=201326592" + pjlFF
		}
		return "@PJL INFO\r\n?" + pjlFF
	case pjlKindFS:
		return "@PJL " + c.verb + " FILEERROR=3" + pjlFF
	case pjlKindSet:
		return "@PJL " + c.verb + " ?" + pjlFF
	case pjlKindJob:
		switch c.verb {
		case "ECHO":
			return "@PJL ECHO" + pjlFF
		case "USTATUS":
			return "@PJL USTATUS DEVICE\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE" + pjlFF
		case "INQUIRE", "DINQUIRE":
			return "@PJL " + c.verb + "\r\n?" + pjlFF
		}
		return ""
	}
	return "@PJL ?" + pjlFF
}

// stripUEL removes every UEL sequence from b and reports whether one was found.
func stripUEL(b []byte) ([]byte, bool) {
	if !bytes.Contains(b, pjlUEL) {
		return b, false
	}
	return bytes.ReplaceAll(b, pjlUEL, nil), true
}

// printableSample returns at most n bytes of b with every non-printable byte
// replaced by '.', so binary print data never reaches a log line as is.
func printableSample(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7F {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

// pjlDataRun accumulates consecutive print data chunks. Only the length, a
// running hash and the first pjlSampleBytes bytes are kept.
type pjlDataRun struct {
	n      int
	h      hash.Hash
	sample []byte
}

func (d *pjlDataRun) add(chunk []byte) {
	if d.h == nil {
		d.h = sha256.New()
	}
	d.n += len(chunk)
	d.h.Write(chunk)
	if room := pjlSampleBytes - len(d.sample); room > 0 {
		d.sample = append(d.sample, chunk[:min(room, len(chunk))]...)
	}
}

func (d *pjlDataRun) hashHex() string {
	return hex.EncodeToString(d.h.Sum(nil))[:pjlHashHexLen]
}

// readPJLChunk reads up to the next newline, or up to pjlMaxChunk bytes of
// binary data, whichever comes first. r must have a buffer of pjlMaxChunk bytes.
func readPJLChunk(r *bufio.Reader) ([]byte, error) {
	chunk, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		err = nil
	}
	return chunk, err
}

func (t *PJLTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	r := bufio.NewReaderSize(conn, pjlMaxChunk)
	var run pjlDataRun
	events, total := 0, 0

	flush := func() {
		if run.n == 0 {
			return
		}
		sum := run.hashHex()
		sess.LogPayloadSize("pjl_data", run.n,
			slog.Int("bytes", run.n),
			slog.String("sha256", sum),
			slog.String("sample", logScrubSecrets(printableSample(run.sample, pjlSampleBytes))))
		sess.Alert(ctx, map[string]string{
			"kind":       pjlKindPrintData,
			"data_bytes": strconv.Itoa(run.n),
			"data_hash":  sum,
		})
		run = pjlDataRun{}
	}
	defer flush()

	for events < pjlMaxEvents {
		chunk, err := readPJLChunk(r)
		total += len(chunk)
		if len(chunk) > 0 {
			stripped, _ := stripUEL(chunk)
			line := strings.TrimSpace(string(stripped))
			cmd, isPJL := classifyPJL(line)
			switch {
			case isPJL:
				flush()
				events++
				if !t.command(ctx, conn, sess, cmd, line) {
					return
				}
			case len(bytes.TrimSpace(stripped)) > 0:
				run.add(stripped)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				setOutcome(sess, err)
			}
			return
		}
		if total > pjlMaxTotal {
			sess.SetOutcome(outcomeTooLong)
			return
		}
	}
}

// command records and answers one PJL command. It reports false when the
// connection failed.
func (t *PJLTrap) command(ctx context.Context, conn net.Conn, sess *Session, c pjlCommand, line string) bool {
	if pjlAttack(c.kind) {
		sess.LogCommand(logCommandText(line), slog.String("kind", c.kind), slog.String("pjl_command", c.verb))
		sess.Alert(ctx, map[string]string{
			"kind":    c.kind,
			"command": metaCommandText(line),
		})
	} else {
		sess.Log("pjl_request", slog.String("kind", c.kind), slog.String("pjl_command", c.verb), slog.String("info", c.what))
	}
	if resp := pjlResponse(c); resp != "" {
		if _, err := io.WriteString(conn, resp); err != nil {
			setOutcome(sess, err)
			return false
		}
	}
	return true
}
