package trap

import (
	"encoding/binary"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func buildModbusTrap(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewModbus(c, l, m, lim, r)
}

func modbusData(words ...uint16) []byte {
	var b []byte
	for _, w := range words {
		b = binary.BigEndian.AppendUint16(b, w)
	}
	return b
}

func TestModbusKindTable(t *testing.T) {
	t.Parallel()
	want := map[byte]modbusKind{
		1: modbusRead, 2: modbusRead, 3: modbusRead, 4: modbusRead, 43: modbusRead,
		5: modbusWrite, 6: modbusWrite, 15: modbusWrite, 16: modbusWrite, 22: modbusWrite, 23: modbusWrite,
		0: modbusUnknown, 7: modbusUnknown, 8: modbusUnknown, 17: modbusUnknown, 42: modbusUnknown, 90: modbusUnknown, 255: modbusUnknown,
	}
	for fc, kind := range want {
		if got := modbusKindOf(fc); got != kind {
			t.Errorf("modbusKindOf(%d) = %d, want %d", fc, got, kind)
		}
	}
}

func TestParseModbusPDUTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		fc   byte
		data []byte
		want map[string]int
	}{
		{"read coils", 1, modbusData(100, 25), map[string]int{"starting_address": 100, "quantity": 25}},
		{"read coils capped", 1, modbusData(0, 65535), map[string]int{"quantity": 2000}},
		{"read holding capped", 3, modbusData(7, 5000), map[string]int{"starting_address": 7, "quantity": 125}},
		{"read input at limit", 4, modbusData(0, 125), map[string]int{"quantity": 125}},
		{"write coil", 5, modbusData(3, 0xFF00), map[string]int{"address": 3, "value": 0xFF00}},
		{"write register", 6, modbusData(0x10, 0xFF), map[string]int{"address": 16, "value": 255}},
		{"write coils capped", 15, modbusData(1, 60000, 1), map[string]int{"address": 1, "quantity": 1968}},
		{"write registers capped", 16, modbusData(2, 9999), map[string]int{"address": 2, "quantity": 123}},
		{"mask write", 22, modbusData(4, 0xF2F2, 0x2525), map[string]int{"address": 4, "and_mask": 0xF2F2, "or_mask": 0x2525}},
		{"read write registers", 23, modbusData(1, 9999, 2, 9999), map[string]int{"starting_address": 1, "quantity": 125, "address": 2, "write_quantity": 121}},
		{"device id", 43, []byte{0x0E, 1, 0}, map[string]int{"mei_type": 14}},
		{"short read", 3, []byte{0, 1}, map[string]int{}},
		{"short mask write", 22, modbusData(1, 2), map[string]int{}},
		{"short read write", 23, modbusData(1, 2, 3), map[string]int{}},
		{"device id empty", 43, nil, map[string]int{}},
		{"unknown", 90, modbusData(1, 2), map[string]int{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attrs := parseModbusPDU(tc.fc, tc.data)
			got := map[string]int{}
			for _, a := range attrs {
				got[a.Key] = int(a.Value.Int64())
			}
			if got["function_code"] != int(tc.fc) {
				t.Errorf("function_code = %d", got["function_code"])
			}
			delete(got, "function_code")
			if len(tc.want) == 0 && len(got) != 0 {
				t.Errorf("attrs = %v, want none", got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
				}
			}
		})
	}
}

func TestModbusReadStaysProbe(t *testing.T) {
	t.Parallel()
	for _, fc := range []byte{1, 2, 3, 4, 43} {
		d := startDepthTrap(t, "modbus", nil, buildModbusTrap)
		conn := dialTrap(t, d.addr)
		data := modbusData(10, 5000)
		if fc == 43 {
			data = []byte{0x0E, 1, 0}
		}
		_, _ = conn.Write(buildModbusRequest(1, 1, fc, data))
		resp := make([]byte, 9)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("fc %d: %v", fc, err)
		}
		if resp[7] != fc|0x80 {
			t.Errorf("fc %d: exception fc = 0x%02x", fc, resp[7])
		}
		conn.Close()
		if got := d.sink.waitOutcome(t); got != alert.ClassProbe {
			t.Errorf("fc %d: class = %s, want probe", fc, got)
		}
		if hasClass(d.sink.snapshot(), alert.ClassAttack) {
			t.Errorf("fc %d: read must not produce an attack event", fc)
		}
	}
}

func TestModbusWriteAndUnknownAreAttack(t *testing.T) {
	t.Parallel()
	cases := []struct {
		fc   byte
		data []byte
		meta map[string]string
	}{
		{6, modbusData(0x10, 0xFF), map[string]string{"function_code": "6", "address": "16", "value": "255"}},
		{16, modbusData(0, 9999, 0), map[string]string{"function_code": "16", "quantity": "123"}},
		{90, nil, map[string]string{"function_code": "90"}},
	}
	for _, tc := range cases {
		d := startDepthTrap(t, "modbus", nil, buildModbusTrap)
		conn := dialTrap(t, d.addr)
		_, _ = conn.Write(buildModbusRequest(1, 1, tc.fc, tc.data))
		resp := make([]byte, 9)
		_, _ = io.ReadFull(conn, resp)
		evs := d.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
		meta := evs[0].Meta
		for k, v := range tc.meta {
			if meta[k] != v {
				t.Errorf("fc %d: meta[%s] = %q, want %q (%v)", tc.fc, k, meta[k], v, meta)
			}
		}
		conn.Close()
	}
}

func TestModbusReadThenWriteEscalates(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "modbus", nil, buildModbusTrap)
	conn := dialTrap(t, d.addr)
	resp := make([]byte, 9)
	_, _ = conn.Write(buildModbusRequest(1, 1, 3, modbusData(0, 1)))
	_, _ = io.ReadFull(conn, resp)
	if hasClass(d.sink.snapshot(), alert.ClassAttack) {
		t.Fatal("attack after read only")
	}
	_, _ = conn.Write(buildModbusRequest(2, 1, 6, modbusData(0, 1)))
	_, _ = io.ReadFull(conn, resp)
	d.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	if !strings.Contains(d.logs.String(), `"action":"probe"`) {
		t.Error("read request should be logged as a probe event")
	}
}
