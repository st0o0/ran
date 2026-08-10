package trap

import "encoding/binary"

func berLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(length))
	i := 0
	for i < 3 && buf[i] == 0 {
		i++
	}
	numBytes := 4 - i
	result := make([]byte, 1+numBytes)
	result[0] = byte(0x80 | numBytes)
	copy(result[1:], buf[i:])
	return result
}

func berInteger(tag byte, val int64) []byte {
	var valBytes []byte
	if val == 0 {
		valBytes = []byte{0}
	} else {
		tmp := val
		for tmp > 0 {
			valBytes = append([]byte{byte(tmp & 0xff)}, valBytes...)
			tmp >>= 8
		}
		if valBytes[0]&0x80 != 0 {
			valBytes = append([]byte{0}, valBytes...)
		}
	}
	result := []byte{tag}
	result = append(result, berLength(len(valBytes))...)
	result = append(result, valBytes...)
	return result
}

func berOctetString(tag byte, data []byte) []byte {
	result := []byte{tag}
	result = append(result, berLength(len(data))...)
	result = append(result, data...)
	return result
}

func berSequence(tag byte, children ...[]byte) []byte {
	var payload []byte
	for _, c := range children {
		payload = append(payload, c...)
	}
	result := []byte{tag}
	result = append(result, berLength(len(payload))...)
	result = append(result, payload...)
	return result
}
