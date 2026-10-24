package trap

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	adbCmdCNXN = 0x4e584e43
	adbCmdAUTH = 0x48545541
	adbCmdOPEN = 0x4e45504f
	adbCmdCLSE = 0x45534c43
	adbHdrSize = 24

	// ADB AUTH types (arg0 of an AUTH packet).
	adbAuthToken     = 1
	adbAuthSignature = 2
	adbAuthPublicKey = 3

	// adbMaxData bounds the data of one packet.
	adbMaxData = 4096
	// adbMaxPostAuthPackets bounds the packets read after the AUTH token.
	adbMaxPostAuthPackets = 8
)

type ADBTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewADB(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *ADBTrap {
	t := &ADBTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("adb", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *ADBTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	hdr := make([]byte, adbHdrSize)
	if _, err := readFull(conn, hdr); err != nil {
		setOutcome(sess, err)
		return
	}

	cmd := binary.LittleEndian.Uint32(hdr[0:4])
	if cmd != adbCmdCNXN {
		sess.LogPayload("adb_unknown", slog.String("raw", fmt.Sprintf("%x", hdr)))
		return
	}

	dataLen := min(binary.LittleEndian.Uint32(hdr[12:16]), adbMaxData)

	var identity string
	if dataLen > 0 {
		payload := make([]byte, dataLen)
		if _, err := readFull(conn, payload); err == nil {
			identity = string(payload)
		}
	}

	sess.LogPayload("adb_identity", slog.String("identity", identity))
	sess.Alert(ctx, map[string]string{"identity": identity})

	if _, err := conn.Write(buildADBAuthToken()); err != nil {
		setOutcome(sess, err)
		return
	}

	t.postAuth(ctx, conn, sess)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func buildADBAuthToken() []byte {
	token := make([]byte, 20)
	_, _ = rand.Read(token)
	resp := make([]byte, adbHdrSize+len(token))
	binary.LittleEndian.PutUint32(resp[0:4], adbCmdAUTH)
	binary.LittleEndian.PutUint32(resp[4:8], adbAuthToken)
	binary.LittleEndian.PutUint32(resp[8:12], 0)
	binary.LittleEndian.PutUint32(resp[12:16], uint32(len(token)))
	copy(resp[adbHdrSize:], token)
	return resp
}

func buildADBClose(localID, remoteID uint32) []byte {
	pkt := make([]byte, adbHdrSize)
	binary.LittleEndian.PutUint32(pkt[0:4], adbCmdCLSE)
	binary.LittleEndian.PutUint32(pkt[4:8], localID)
	binary.LittleEndian.PutUint32(pkt[8:12], remoteID)
	return pkt
}

// readADBPacket reads one ADB packet. The data length is checked against
// adbMaxData before anything is allocated, so the result is never larger than
// the bytes actually read from r. A longer declared length is bufio.ErrTooLong.
func readADBPacket(r io.Reader) (cmd, arg0, arg1 uint32, data []byte, err error) {
	var hdr [adbHdrSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	cmd = binary.LittleEndian.Uint32(hdr[0:4])
	arg0 = binary.LittleEndian.Uint32(hdr[4:8])
	arg1 = binary.LittleEndian.Uint32(hdr[8:12])
	n, ok := fitsInt(binary.LittleEndian.Uint32(hdr[12:16]), adbMaxData)
	if !ok {
		return cmd, arg0, arg1, nil, bufio.ErrTooLong
	}
	data = make([]byte, n)
	if _, err = io.ReadFull(r, data); err != nil {
		return cmd, arg0, arg1, nil, err
	}
	return cmd, arg0, arg1, data, nil
}

// adbShellCommand returns the command of an OPEN destination that starts with
// shell: or exec:, cut to 256 bytes with control characters replaced.
func adbShellCommand(dest []byte) (string, bool) {
	s := strings.TrimRight(string(dest), "\x00")
	for _, prefix := range []string{"shell:", "exec:"} {
		if strings.HasPrefix(s, prefix) {
			return alert.SanitizeValue(s), true
		}
	}
	return "", false
}

// postAuth reads the packets that follow the AUTH token: a signature or public
// key is an auth attempt (only a hash of the key is kept), OPEN shell:/exec: is
// a command and is answered with CLSE. A silent client ends at the session
// deadline with outcome timeout.
func (t *ADBTrap) postAuth(ctx context.Context, conn net.Conn, sess *Session) {
	for range adbMaxPostAuthPackets {
		cmd, arg0, _, data, err := readADBPacket(conn)
		if err != nil {
			// A client that simply hangs up after the token is a normal end.
			if !errors.Is(err, io.EOF) {
				sess.setReadOutcome(err)
			}
			return
		}
		switch cmd {
		case adbCmdAUTH:
			var method string
			switch arg0 {
			case adbAuthSignature:
				method = "adb_signature"
			case adbAuthPublicKey:
				method = "adb_publickey"
			default:
				continue
			}
			sum := sha256.Sum256(data)
			keyHash := hex.EncodeToString(sum[:])
			sess.LogAuthAttempt(slog.String("method", method), slog.String("key_hash", keyHash))
			sess.RecordCredentials(t.metrics)
			sess.Alert(ctx, map[string]string{"method": method, "key_hash": keyHash})
			if arg0 == adbAuthSignature {
				// A real adbd answers a rejected signature with a new token,
				// after which the client offers its public key.
				if _, err := conn.Write(buildADBAuthToken()); err != nil {
					setOutcome(sess, err)
					return
				}
			}
		case adbCmdOPEN:
			command, ok := adbShellCommand(data)
			if !ok {
				continue
			}
			sess.LogCommand(command)
			sess.Alert(ctx, map[string]string{"command": command})
			_, _ = conn.Write(buildADBClose(0, arg0))
			return
		}
	}
}
