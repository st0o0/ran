package trap

import "bufio"

const maxLineLen = 4096

// readLineLimited reads up to and including the next '\n' without buffering
// more than max bytes. It returns bufio.ErrTooLong once the line exceeds max.
func readLineLimited(r *bufio.Reader, max int) (string, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > max {
			return "", bufio.ErrTooLong
		}
		buf = append(buf, chunk...)
		switch err {
		case nil:
			return string(buf), nil
		case bufio.ErrBufferFull:
			continue
		default:
			return "", err
		}
	}
}
