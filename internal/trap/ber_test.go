package trap

import (
	"bytes"
	"math"
	"testing"
)

func TestBerLengthShortForm(t *testing.T) {
	got := berLength(5)
	if !bytes.Equal(got, []byte{5}) {
		t.Errorf("berLength(5) = %x, want 05", got)
	}
}

func TestBerLengthLongForm(t *testing.T) {
	got := berLength(200)
	if !bytes.Equal(got, []byte{0x81, 200}) {
		t.Errorf("berLength(200) = %x, want 81c8", got)
	}
}

func TestBerLengthTwoBytes(t *testing.T) {
	got := berLength(300)
	if !bytes.Equal(got, []byte{0x82, 0x01, 0x2C}) {
		t.Errorf("berLength(300) = %x, want 8201 2c", got)
	}
}

func TestBerIntegerZero(t *testing.T) {
	got := berInteger(0x02, 0)
	if !bytes.Equal(got, []byte{0x02, 0x01, 0x00}) {
		t.Errorf("berInteger(0x02, 0) = %x, want 020100", got)
	}
}

func TestBerIntegerSmall(t *testing.T) {
	got := berInteger(0x02, 42)
	if !bytes.Equal(got, []byte{0x02, 0x01, 0x2a}) {
		t.Errorf("berInteger(0x02, 42) = %x, want 02012a", got)
	}
}

func TestBerIntegerHighBit(t *testing.T) {
	got := berInteger(0x02, 128)
	if !bytes.Equal(got, []byte{0x02, 0x02, 0x00, 0x80}) {
		t.Errorf("berInteger(0x02, 128) = %x, want 02020080", got)
	}
}

func TestBerIntegerCustomTag(t *testing.T) {
	got := berInteger(0x0a, 3)
	if got[0] != 0x0a {
		t.Errorf("tag = 0x%02x, want 0x0a", got[0])
	}
}

func TestBerOctetStringEmpty(t *testing.T) {
	got := berOctetString(0x04, nil)
	if !bytes.Equal(got, []byte{0x04, 0x00}) {
		t.Errorf("berOctetString(0x04, nil) = %x, want 0400", got)
	}
}

func TestBerOctetStringData(t *testing.T) {
	got := berOctetString(0x04, []byte("abc"))
	if !bytes.Equal(got, []byte{0x04, 0x03, 'a', 'b', 'c'}) {
		t.Errorf("berOctetString(0x04, abc) = %x", got)
	}
}

func TestBerSequenceEmpty(t *testing.T) {
	got := berSequence(0x30)
	if !bytes.Equal(got, []byte{0x30, 0x00}) {
		t.Errorf("berSequence(0x30) = %x, want 3000", got)
	}
}

func TestBerSequenceWithChildren(t *testing.T) {
	child1 := berInteger(0x02, 1)
	child2 := berOctetString(0x04, []byte("x"))
	got := berSequence(0x30, child1, child2)

	if got[0] != 0x30 {
		t.Errorf("tag = 0x%02x, want 0x30", got[0])
	}
	expectedLen := len(child1) + len(child2)
	if int(got[1]) != expectedLen {
		t.Errorf("length = %d, want %d", got[1], expectedLen)
	}
}

func TestBerSequenceCustomTag(t *testing.T) {
	got := berSequence(0x61, berInteger(0x0a, 0))
	if got[0] != 0x61 {
		t.Errorf("tag = 0x%02x, want 0x61", got[0])
	}
}

func TestBerIntegerNegative(t *testing.T) {
	cases := []struct {
		val  int64
		want []byte
	}{
		{-1, []byte{0x02, 0x01, 0xFF}},
		{-128, []byte{0x02, 0x01, 0x80}},
		{-129, []byte{0x02, 0x02, 0xFF, 0x7F}},
		{-1 << 63, []byte{0x02, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0}},
		{1<<63 - 1, []byte{0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		got := berInteger(0x02, tc.val)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("berInteger(%d) = %x, want %x", tc.val, got, tc.want)
		}
		back, _, err := berReadInteger(got)
		if err != nil || back != tc.val {
			t.Errorf("round trip of %d = %d, %v", tc.val, back, err)
		}
	}
}

// A client controlled LDAP message ID such as 0xFFFFFFFFFFFFFFFF is echoed
// back in the response and used to panic the encoder.
func TestBerNegativeMessageID(t *testing.T) {
	msg := []byte{0x02, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	id, _, err := berReadInteger(msg)
	if err != nil || id != -1 {
		t.Fatalf("id = %d, err = %v", id, err)
	}
	if resp := berBuildBindResponse(id, 49, "", "x"); len(resp) == 0 {
		t.Fatal("empty bind response")
	}
	if resp := berBuildSearchDone(id, 50); len(resp) == 0 {
		t.Fatal("empty search done response")
	}
}

func TestFitsInt(t *testing.T) {
	cases := []struct {
		v      uint32
		maxInt uint64
		want   int
		ok     bool
	}{
		{0, math.MaxInt32, 0, true},
		{math.MaxInt32, math.MaxInt32, math.MaxInt32, true},
		{math.MaxInt32 + 1, math.MaxInt32, 0, false}, // negative as a 32-bit int
		{math.MaxUint32, math.MaxInt32, 0, false},
	}
	for _, tc := range cases {
		got, ok := fitsInt(tc.v, tc.maxInt)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("fitsInt(%d, %d) = %d, %v", tc.v, tc.maxInt, got, ok)
		}
	}
}

func TestBERReadIntegerLengthLimits(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"length 0", []byte{0x02, 0x00}, true},
		{"length 9", append([]byte{0x02, 0x09}, make([]byte, 9)...), true},
		{"length 1", []byte{0x02, 0x01, 0x05}, false},
		{"length 8", append([]byte{0x02, 0x08}, make([]byte, 8)...), false},
		{"length 8 truncated", []byte{0x02, 0x08, 0x01}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := berReadInteger(tc.data)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
