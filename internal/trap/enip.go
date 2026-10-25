package trap

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	enipHdrSize = 24
	// enipMaxData bounds the data of one encapsulation packet; the protocol
	// allows 65535 bytes, real traffic from scanners is far below this.
	enipMaxData = 1024
	// enipMaxPackets bounds the packets served per session.
	enipMaxPackets = 64

	enipNOP               = 0x0000
	enipListServices      = 0x0004
	enipListIdentity      = 0x0063
	enipListInterfaces    = 0x0064
	enipRegisterSession   = 0x0065
	enipUnRegisterSession = 0x0066
	enipSendRRData        = 0x006F
	enipSendUnitData      = 0x0070

	// enipSessionHandle is the fixed handle handed out by RegisterSession.
	enipSessionHandle = 0x0001A2B3

	enipStatusUnsupported = 0x0001

	enipKindNOP           = "nop"
	enipKindListIdentity  = "list_identity"
	enipKindListServices  = "list_services"
	enipKindListInterface = "list_interfaces"
	enipKindRegister      = "register_session"
	enipKindUnregister    = "unregister_session"
	enipKindSendData      = "send_data"
	enipKindUnknown       = "unknown"
)

// ENIPTrap is a stub of an EtherNet/IP device (TCP 44818). Session and listing
// commands are answered with a fixed identity; SendRRData, SendUnitData and any
// unknown command are payload and refused with an encapsulation status.
type ENIPTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewENIP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *ENIPTrap {
	t := &ENIPTrap{cfg: cfg, logger: logger, metrics: m}
	t.tcpServer = newTCPServer("enip", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

// enipPacket is one decoded encapsulation packet.
type enipPacket struct {
	command uint16
	session uint32
	context [8]byte
	data    []byte
}

// readENIP reads one encapsulation packet. The declared data length is checked
// against enipMaxData before anything is allocated; a longer one is
// bufio.ErrTooLong, so the data is never larger than the bytes read.
func readENIP(r io.Reader) (enipPacket, error) {
	var hdr [enipHdrSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return enipPacket{}, err
	}
	p := enipPacket{
		command: binary.LittleEndian.Uint16(hdr[0:2]),
		session: binary.LittleEndian.Uint32(hdr[4:8]),
	}
	copy(p.context[:], hdr[12:20])
	n, ok := fitsInt(uint32(binary.LittleEndian.Uint16(hdr[2:4])), enipMaxData)
	if !ok {
		return p, bufio.ErrTooLong
	}
	p.data = make([]byte, n)
	if _, err := io.ReadFull(r, p.data); err != nil {
		return p, err
	}
	return p, nil
}

// enipKindOf maps a command to its kind; send_data and unknown are the attack kinds.
func enipKindOf(cmd uint16) string {
	switch cmd {
	case enipNOP:
		return enipKindNOP
	case enipListServices:
		return enipKindListServices
	case enipListIdentity:
		return enipKindListIdentity
	case enipListInterfaces:
		return enipKindListInterface
	case enipRegisterSession:
		return enipKindRegister
	case enipUnRegisterSession:
		return enipKindUnregister
	case enipSendRRData, enipSendUnitData:
		return enipKindSendData
	default:
		return enipKindUnknown
	}
}

// enipCIPService returns the CIP service code of a SendRRData or SendUnitData
// packet (the first byte of the unconnected or connected data item), or -1. It
// reads at most four items and never reads outside data.
func enipCIPService(cmd uint16, data []byte) int {
	if cmd != enipSendRRData && cmd != enipSendUnitData {
		return -1
	}
	// Interface handle (4), timeout (2), item count (2).
	if len(data) < 8 {
		return -1
	}
	count := int(binary.LittleEndian.Uint16(data[6:8]))
	off := 8
	for i := 0; i < min(count, 4); i++ {
		if off+4 > len(data) {
			return -1
		}
		typ := binary.LittleEndian.Uint16(data[off : off+2])
		l := int(binary.LittleEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if off+l > len(data) {
			return -1
		}
		item := data[off : off+l]
		off += l
		switch typ {
		case 0x00B2:
			if len(item) >= 1 {
				return int(item[0])
			}
		case 0x00B1:
			// Connected data item: a 2 byte sequence count precedes the CIP request.
			if len(item) >= 3 {
				return int(item[2])
			}
		}
	}
	return -1
}

func enipHeader(cmd uint16, session uint32, status uint32, ctxBytes [8]byte, data []byte) []byte {
	out := make([]byte, enipHdrSize, enipHdrSize+len(data))
	binary.LittleEndian.PutUint16(out[0:2], cmd)
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(data)))
	binary.LittleEndian.PutUint32(out[4:8], session)
	binary.LittleEndian.PutUint32(out[8:12], status)
	copy(out[12:20], ctxBytes[:])
	return append(out, data...)
}

// enipIdentityItem is the fixed CIP identity item (type 0x000C). The values are
// invented: vendor 1 and device type 14 are registry values, the rest is not a
// real device.
func enipIdentityItem() []byte {
	name := "1769-L33ER/A LOGIX5333ER"
	b := binary.LittleEndian.AppendUint16(nil, 1) // encapsulation protocol version
	// Socket address, big endian: family AF_INET, port 44818, address 0.0.0.0.
	b = append(b, 0x00, 0x02, 0xAF, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	b = binary.LittleEndian.AppendUint16(b, 1)    // vendor ID
	b = binary.LittleEndian.AppendUint16(b, 14)   // device type
	b = binary.LittleEndian.AppendUint16(b, 166)  // product code
	b = append(b, 20, 11)                         // revision
	b = binary.LittleEndian.AppendUint16(b, 0x30) // status
	b = binary.LittleEndian.AppendUint32(b, 0x00C0FFEE)
	b = append(b, byte(len(name)))
	b = append(b, name...)
	b = append(b, 3) // state: operational
	item := binary.LittleEndian.AppendUint16(nil, 0x000C)
	item = binary.LittleEndian.AppendUint16(item, uint16(len(b)))
	return append(item, b...)
}

func enipListIdentityData() []byte {
	return append(binary.LittleEndian.AppendUint16(nil, 1), enipIdentityItem()...)
}

// enipListServicesData is one "Communications" service item.
func enipListServicesData() []byte {
	b := binary.LittleEndian.AppendUint16(nil, 1) // item count
	b = binary.LittleEndian.AppendUint16(b, 0x0100)
	b = binary.LittleEndian.AppendUint16(b, 20)
	b = binary.LittleEndian.AppendUint16(b, 1)      // version
	b = binary.LittleEndian.AppendUint16(b, 0x0120) // capability flags
	return append(b, padTo("Communications", 16)...)
}

// enipResponse builds the answer to a packet, or nil when none is sent.
func enipResponse(p enipPacket) []byte {
	switch p.command {
	case enipNOP, enipUnRegisterSession:
		return nil
	case enipListIdentity:
		return enipHeader(p.command, 0, 0, p.context, enipListIdentityData())
	case enipListServices:
		return enipHeader(p.command, 0, 0, p.context, enipListServicesData())
	case enipListInterfaces:
		return enipHeader(p.command, 0, 0, p.context, binary.LittleEndian.AppendUint16(nil, 0))
	case enipRegisterSession:
		data := []byte{1, 0, 0, 0}
		return enipHeader(p.command, enipSessionHandle, 0, p.context, data)
	default:
		return enipHeader(p.command, p.session, enipStatusUnsupported, p.context, nil)
	}
}

func (t *ENIPTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	for range enipMaxPackets {
		p, err := readENIP(conn)
		if err != nil {
			setOutcome(sess, err)
			return
		}
		kind := enipKindOf(p.command)
		switch kind {
		case enipKindSendData, enipKindUnknown:
			attrs := []slog.Attr{slog.String("kind", kind), slog.Int("command_code", int(p.command))}
			meta := map[string]string{"kind": kind, "command_code": strconv.Itoa(int(p.command))}
			if svc := enipCIPService(p.command, p.data); svc >= 0 {
				attrs = append(attrs, slog.Int("cip_service", svc))
				meta["cip_service"] = strconv.Itoa(svc)
			}
			sess.LogPayloadSize("enip_request", enipHdrSize+len(p.data), attrs...)
			sess.Alert(ctx, meta)
		default:
			sess.Log("enip_request", slog.String("kind", kind))
		}

		if p.command == enipUnRegisterSession {
			return
		}
		if resp := enipResponse(p); resp != nil {
			if _, err := conn.Write(resp); err != nil {
				setOutcome(sess, err)
				return
			}
		}
	}
}
