package trap

// Telnet command bytes (RFC 854) and the option the trap understands.
const (
	telnetIAC  = 255
	telnetDONT = 254
	telnetDO   = 253
	telnetWONT = 252
	telnetWILL = 251
	telnetSB   = 250
	telnetSE   = 240

	telnetOptTTYPE = 24
	telnetTTYPEIs  = 0

	// maxTelnetTType bounds the logged terminal type.
	maxTelnetTType = 64
	// maxTelnetReplyBytes bounds the negotiation replies per input line, so a
	// stream of options cannot be amplified into a large write.
	maxTelnetReplyBytes = 192
)

// parseTelnetIAC splits raw telnet input into the application data and the
// negotiation answers. IAC IAC is a literal 0xFF; WILL is answered with DONT
// and DO with WONT (DONT and WONT need no answer); other commands are dropped;
// a subnegotiation is consumed up to IAC SE and, for the terminal type (IS),
// reported bounded to maxTelnetTType bytes of printable ASCII. A sequence cut
// off by the end of the input is dropped. clean and replies are never longer
// than in, and ttype never longer than maxTelnetTType.
func parseTelnetIAC(in []byte) (clean, replies []byte, ttype string) {
	clean = make([]byte, 0, len(in))
	for i := 0; i < len(in); {
		b := in[i]
		if b != telnetIAC {
			clean = append(clean, b)
			i++
			continue
		}
		if i+1 >= len(in) {
			break // lone IAC at the end
		}
		switch cmd := in[i+1]; cmd {
		case telnetIAC:
			clean = append(clean, telnetIAC)
			i += 2
		case telnetDO, telnetDONT, telnetWILL, telnetWONT:
			if i+2 >= len(in) {
				return clean, replies, ttype // truncated option
			}
			opt := in[i+2]
			if len(replies)+3 <= maxTelnetReplyBytes {
				switch cmd {
				case telnetDO:
					replies = append(replies, telnetIAC, telnetWONT, opt)
				case telnetWILL:
					replies = append(replies, telnetIAC, telnetDONT, opt)
				}
			}
			i += 3
		case telnetSB:
			end := -1
			for j := i + 2; j+1 < len(in); j++ {
				if in[j] == telnetIAC && in[j+1] == telnetSE {
					end = j
					break
				}
			}
			if end < 0 {
				return clean, replies, ttype // unterminated subnegotiation
			}
			body := in[i+2 : end]
			if len(body) >= 2 && body[0] == telnetOptTTYPE && body[1] == telnetTTYPEIs {
				ttype = printableBounded(body[2:], maxTelnetTType)
			}
			i = end + 2
		default:
			i += 2 // NOP, GA and the other two byte commands
		}
	}
	return clean, replies, ttype
}

// printableBounded keeps the printable ASCII bytes of b, at most limit of them.
func printableBounded(b []byte, limit int) string {
	out := make([]byte, 0, min(len(b), limit))
	for _, c := range b {
		if len(out) >= limit {
			break
		}
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}
