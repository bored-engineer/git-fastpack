package fastpack

import (
	"errors"
	"fmt"
)

// the maximum number of bytes a LEB128 encoding count be (64/7)
const maxLEB128Width = 10

// decodeLEB128 parses an unsigned LEB128-encoded integer from the input byte slice
func decodeLEB128(input []byte) (res uint64, remaining []byte, err error) {
	remaining = input
	for idx := range maxLEB128Width {
		var b byte
		b, remaining = remaining[0], remaining[1:]

		if idx == maxLEB128Width-1 && b > 1 {
			return 0, nil, errors.New("invalid LEB128: overflow while decoding")
		}
		res |= uint64(b&0x7f) << (7 * idx)
		if b&0x80 == 0 {
			return res, remaining, nil
		}
	}
	return 0, nil, errors.New("invalid LEB128 encoding")
}

// decodeOffsetSize decodes the offset and size from a delta command byte and the following bytes in the delta data.
func decodeOffsetSize(cmd byte, delta []byte) (uint32, uint32, []byte, error) {
	var offset, size uint32

	// offset
	if (cmd & 0x01) != 0 {
		if len(delta) == 0 {
			return 0, 0, nil, errors.New("invalid delta")
		}
		offset |= uint32(delta[0]) << 0
		delta = delta[1:]
	}
	if (cmd & 0x02) != 0 {
		if len(delta) == 0 {
			return 0, 0, nil, errors.New("invalid delta")
		}
		offset |= uint32(delta[0]) << 8
		delta = delta[1:]
	}
	if (cmd & 0x04) != 0 {
		if len(delta) == 0 {
			return 0, 0, nil, errors.New("invalid delta")
		}
		offset |= uint32(delta[0]) << 16
		delta = delta[1:]
	}
	if (cmd & 0x08) != 0 {
		if len(delta) == 0 {
			return 0, 0, nil, errors.New("invalid delta")
		}
		offset |= uint32(delta[0]) << 24
		delta = delta[1:]
	}

	// size
	if (cmd & 0x10) != 0 {
		if len(delta) == 0 {
			return 0, 0, nil, errors.New("invalid size")
		}
		size |= uint32(delta[0]) << 0
		delta = delta[1:]
	}
	if (cmd & 0x20) != 0 {
		if len(delta) == 0 {
			return 0, 0, nil, errors.New("invalid size")
		}
		size |= uint32(delta[0]) << 8
		delta = delta[1:]
	}
	if (cmd & 0x40) != 0 {
		if len(delta) == 0 {
			return 0, 0, nil, errors.New("invalid size")
		}
		size |= uint32(delta[0]) << 16
		delta = delta[1:]
	}

	// There is another exception: size zero is automatically converted to 0x10000
	if size == 0 {
		size = 64 * 1024
	}

	return offset, size, delta, nil
}

// Implements the "deltified representation" algorithm described in https://git-scm.com/docs/pack-format#_deltified_representation
func applyDelta(src []byte, delta []byte) ([]byte, error) {
	srcSize, delta, err := decodeLEB128(delta)
	if err != nil {
		return nil, fmt.Errorf("invalid delta: failed to decode source size: %w", err)
	}
	if int(srcSize) != len(src) {
		return nil, fmt.Errorf("invalid delta: source size mismatch, expected %d, got %d", srcSize, len(src))
	}
	dstSize, delta, err := decodeLEB128(delta)
	if err != nil {
		return nil, fmt.Errorf("invalid delta: failed to decode destination size: %w", err)
	}
	dst := make([]byte, 0, dstSize)

	for (cap(dst) - len(dst)) > 0 {
		if len(delta) == 0 {
			return nil, fmt.Errorf("invalid delta: delta data ended before destination size was reached")
		}

		cmd := delta[0]
		delta = delta[1:]
		if cmd == 0 {
			// reserved instruction
			return nil, fmt.Errorf("invalid delta command: 0x00")
		} else if cmd&0x80 != 0 {
			// copy-from-src instruction
			offset, size, remaining, err := decodeOffsetSize(cmd, delta)
			if err != nil {
				return nil, err
			}

			if int(size) > cap(dst)-len(dst) {
				return nil, errors.New("invalid delta: exceeds destination size")
			} else if int(offset) > len(src) || int(offset+size) > len(src) {
				return nil, errors.New("invalid delta: offset exceeds source size")
			}

			dst = append(dst, src[offset:offset+size]...)
			delta = remaining
		} else {
			// copy-from-delta instruction
			size := int(cmd)

			if size > len(delta) {
				return nil, errors.New("invalid delta: exceeds source size")
			} else if size > cap(dst)-len(dst) {
				return nil, errors.New("invalid delta: exceeds destination size")
			}

			dst = append(dst, delta[0:size]...)
			delta = delta[size:]
		}
	}

	if len(delta) != 0 {
		return nil, fmt.Errorf("invalid delta: delta data has %d extra bytes after reaching destination size", len(delta))
	}

	return dst, nil
}
