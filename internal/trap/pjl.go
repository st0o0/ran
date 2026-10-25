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
	// pjlMaxEvents bounds the PJL commands served per session. Print data runs do
	// not count; they are bounded by pjlMaxTotal.
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
	pjlSerial = "CNB8K12345"
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
	// arg is the sanitized echo token of an ECHO command (see pjlEchoToken).
	arg string
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
	case verb == "ECHO":
		return pjlCommand{kind: pjlKindJob, verb: verb, arg: pjlEchoToken(line)}, true
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

// pjlMaxEchoBytes bounds the text an ECHO answer reflects.
const pjlMaxEchoBytes = 32

// pjlFilesysInfo is the static answer to @PJL INFO FILESYS: one writable volume.
const pjlFilesysInfo = "@PJL INFO FILESYS\r\n[1 TABLE]\r\nVOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS\r\n" +
	"0: 125829120 98566144 RAM DISK ? READ-WRITE" + pjlFF

// pjlEchoToken returns the text after "@PJL ECHO" cut down to what an ECHO answer
// may reflect: printable ASCII only (every other byte is dropped, which includes
// ESC, so no escape sequence or UEL can come back), trimmed, at most
// pjlMaxEchoBytes bytes. This is the only place where client text reaches a
// response of the pjl trap.
func pjlEchoToken(line string) string {
	rest := strings.TrimSpace(line)
	for range 2 { // skip "@PJL" and "ECHO"
		i := strings.IndexAny(rest, " \t")
		if i < 0 {
			return ""
		}
		rest = strings.TrimLeft(rest[i:], " \t")
	}
	out := make([]byte, 0, pjlMaxEchoBytes)
	for i := 0; i < len(rest) && len(out) < pjlMaxEchoBytes; i++ {
		if c := rest[i]; c >= 0x20 && c < 0x7F {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(string(out))
}

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
		case "FILESYS":
			return pjlFilesysInfo
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
			if c.arg == "" {
				return "@PJL ECHO" + pjlFF
			}
			return "@PJL ECHO " + c.arg + pjlFF
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

// uelStripper removes UEL sequences from a stream of chunks, also when a
// sequence is split across two reads. A trailing partial UEL (at most 9 bytes)
// is held back and prepended to the next chunk; flush returns what is left at
// the end of the stream.
type uelStripper struct{ carry []byte }

func (u *uelStripper) strip(chunk []byte) []byte {
	data := chunk
	if len(u.carry) > 0 {
		data = append(append(make([]byte, 0, len(u.carry)+len(chunk)), u.carry...), chunk...)
		u.carry = nil
	}
	data, _ = stripUEL(data)
	for n := min(len(pjlUEL)-1, len(data)); n > 0; n-- {
		if bytes.HasSuffix(data, pjlUEL[:n]) {
			u.carry = append([]byte(nil), data[len(data)-n:]...)
			return data[:len(data)-n]
		}
	}
	return data
}

func (u *uelStripper) flush() []byte {
	out := u.carry
	u.carry = nil
	return out
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
	var uel uelStripper
	events, total := 0, 0
	first := true

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

	// consume handles UEL-free bytes: PJL commands and print data. A line ends at
	// CR, LF or CRLF. It reports false when the session is over.
	consume := func(piece []byte) bool {
		if first && len(bytes.TrimSpace(piece)) > 0 {
			first = false
			if label := sniffProtocol(piece); label != sniffUnknown {
				// HTTP, TLS, SMB, SSH or RDP on a printer port is cross-protocol
				// noise, not a print job: log it and stay a probe.
				sess.Log("pjl_request", slog.String("kind", "noise"), slog.String("sniffed_protocol", label))
				sess.SetOutcome("probe")
				return false
			}
		}
		for len(piece) > 0 {
			n := len(piece)
			if i := bytes.IndexAny(piece, "\r\n"); i >= 0 {
				n = i + 1
			}
			seg := piece[:n]
			piece = piece[n:]
			line := strings.TrimSpace(string(seg))
			cmd, isPJL := classifyPJL(line)
			switch {
			case isPJL:
				flush()
				events++
				if !t.command(ctx, conn, sess, cmd, line) || events >= pjlMaxEvents {
					return false
				}
			case len(bytes.TrimSpace(seg)) > 0:
				run.add(seg)
			}
		}
		return true
	}

	for {
		chunk, err := readPJLChunk(r)
		total += len(chunk)
		ok := consume(uel.strip(chunk))
		if err != nil {
			if ok {
				consume(uel.flush())
			}
			if !errors.Is(err, io.EOF) {
				setOutcome(sess, err)
			}
			return
		}
		if !ok {
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
