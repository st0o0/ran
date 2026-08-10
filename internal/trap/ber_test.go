package trap

import (
	"bytes"
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
