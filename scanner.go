package fastpack

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"

	libdeflate "github.com/4kills/go-libdeflate/v2/native"
	lru "github.com/hashicorp/golang-lru/v2"
)

type cacheEntry struct {
	objectType ObjectType
	data       []byte
}

// Scanner iterates through the objects in a packfile, returning their type and decompressed data.
type Scanner struct {
	packfile     []byte                      // 24 bytes (slice header)
	offset       int                         // 8 bytes
	decompressor *libdeflate.Decompressor    // 8 bytes
	cache        *lru.Cache[int, cacheEntry] // 8 bytes
}

// readByte reads a single byte from the packfile at the current offset and advances the offset by 1.
func (s *Scanner) readByte() (byte, error) {
	if s.offset >= len(s.packfile) {
		return 0, io.ErrUnexpectedEOF
	}
	b := s.packfile[s.offset]
	s.offset++
	return b, nil
}

// readTypeLength reads the type and length of the next object.
func (s *Scanner) readTypeLength() (ObjectType, uint64, error) {
	// Extract the type from the first byte.
	c, err := s.readByte()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read type/length byte: %w", err)
	}
	// n-byte type and length (3-bit type, (n-1)*7+4-bit length)
	// 0x70: 0111 0000
	shift := uint8(4)
	objectType := ObjectType((c & 0x70) >> shift)
	if !objectType.Valid() {
		return 0, 0, fmt.Errorf("invalid object type: %d", objectType)
	}
	// 0x0F: 0000 1111
	length := uint64(c & 0x0F)
	// 0x80: 1000 0000
	for c&0x80 != 0 {
		if shift > 64-7 {
			return 0, 0, fmt.Errorf("overflow while reading varint: shift=%d", shift)
		}
		// Process the next byte.
		c, err = s.readByte()
		if err != nil {
			return 0, 0, fmt.Errorf("failed to read length byte: %w", err)
		}
		// 0x7F: 0111 1111
		length |= uint64(c&0x7F) << shift
		shift += 7
	}
	return objectType, length, nil
}

// readZlib reads zlib data from the packfile at the current offset
func (s *Scanner) readZlib(out []byte) error {
	n, out2, err := s.decompressor.Decompress(s.packfile[s.offset:], out, libdeflate.DecompressZlib)
	if err != nil {
		return fmt.Errorf("decompression failed: %w", err)
	}
	s.offset += n
	if len(out) != len(out2) {
		return fmt.Errorf("decompression length mismatch: expected %d, got %d", len(out), len(out2))
	}
	return nil
}

// readLength reads a variable-length integer from the reader.
func (s *Scanner) readLength() (int64, error) {
	c, err := s.readByte()
	if err != nil {
		return 0, fmt.Errorf("failed to read varint byte: %w", err)
	}

	// 0x7F: 0111 1111
	v := int64(c & 0x7F)
	// 0x80: 1000 0000
	for c&0x80 > 0 {
		if v >= (math.MaxInt64-int64(0x7F))>>7 {
			return 0, fmt.Errorf("overflow while reading varint")
		}

		v++
		c, err = s.readByte()
		if err != nil {
			return 0, fmt.Errorf("failed to read varint byte: %w", err)
		}

		// 0x07: 0000 0111
		v = (v << 0x07) + int64(c&0x7F)
	}
	return v, nil
}

// Object reads the next object from the packfile, returning its type and decompressed data.
func (s *Scanner) Object() (ObjectType, []byte, error) {
	// Save the offset of the start of the object
	startOffset := s.offset
	// Read the type and decompressed length of the next object.
	objectType, length, err := s.readTypeLength()
	if err != nil {
		return InvalidObject, nil, err
	}
	// For delta objects, read the offset or reference before reading the compressed data.
	var base []byte
	switch objectType {
	case OFSDeltaObject:
		offset, err := s.readLength()
		if err != nil {
			return InvalidObject, nil, fmt.Errorf("failed to read ofs-delta offset: %w", err)
		} else if offset <= 0 || offset > int64(startOffset) {
			return InvalidObject, nil, fmt.Errorf("invalid ofs-delta offset: %d", offset)
		}
		actualOffset := startOffset - int(offset)
		if entry, ok := s.cache.Get(actualOffset); ok {
			objectType = entry.objectType
			base = entry.data
		} else {
			// Save the current offset
			currentOffset := s.offset
			// Seek backwards to the base object and read it to verify the offset is valid.
			s.offset = actualOffset
			// Read the base object
			objectType, base, err = s.Object()
			if err != nil {
				return InvalidObject, nil, fmt.Errorf("failed to read base object: %w", err)
			}
			// Seek back to the original position to prepare for reading the delta.
			s.offset = currentOffset
		}
	case REFDeltaObject:
		return InvalidObject, nil, fmt.Errorf("ref-delta objects are not supported")
	}
	buf := make([]byte, length) // TODO: sync.Pool?
	if err := s.readZlib(buf); err != nil {
		return InvalidObject, nil, fmt.Errorf("failed to read zlib data: %w", err)
	}
	// If it was an ofs-delta, we need to apply the delta to the base object.
	if base != nil {
		// Apply the delta to the base object data.
		buf, err = applyDelta(base, buf)
		if err != nil {
			return InvalidObject, nil, fmt.Errorf("failed to apply delta: %w", err)
		}
	}
	s.cache.Add(startOffset, cacheEntry{objectType: objectType, data: buf})
	return objectType, buf, nil
}

// panicFreeCloser is a type that can be closed without panicking if it is already closed. This is used for AutoClose functionality.
type panicFreeCloser interface {
	PanicFreeClose()
}

// attachAutoClose attaches a finalizer to the given panicFreeCloser that calls PanicFreeClose() when the object is garbage collected.
// Used for AutoClose functionality. Do not call this function directly.
func attachAutoClose(c panicFreeCloser) {
	runtime.SetFinalizer(c, func(finalized panicFreeCloser) {
		println("finalizer")
		finalized.PanicFreeClose()
	})
}

// Header parses the packfile header
func (s *Scanner) Header() (version uint32, objects uint32, err error) {
	// The smallest valid packfile is 12 bytes for the header plus 20 bytes for the checksum, so 32 bytes total.
	if len(s.packfile) < 12+sha1.Size {
		return 0, 0, fmt.Errorf("packfile too short: %d bytes", len(s.packfile))
	}
	header := s.packfile[:12]
	s.offset = 12
	// 4-byte signature: The signature is: {'P', 'A', 'C', 'K'}
	if header[0] != 'P' || header[1] != 'A' || header[2] != 'C' || header[3] != 'K' {
		return 0, 0, fmt.Errorf("invalid packfile header: %X", header[0:4])
	}
	// 4-byte version number (network byte order): Git currently accepts version number 2 or 3 but generates version 2 only.
	if version := binary.BigEndian.Uint32(header[4:8]); version != 2 && version != 3 {
		return 0, 0, fmt.Errorf("unsupported packfile version: %d", version)
	}
	// 4-byte number of objects contained in the pack (network byte order)
	objects = binary.BigEndian.Uint32(header[8:12])
	return version, objects, nil
}

// Trailer parses the packfile trailer and verifies the checksum.
func (s *Scanner) Trailer() ([sha1.Size]byte, error) {
	if len(s.packfile) < sha1.Size {
		return [sha1.Size]byte{}, fmt.Errorf("packfile too short to contain checksum: %d bytes", len(s.packfile))
	}
	expected := s.packfile[len(s.packfile)-sha1.Size:]
	actual := sha1.Sum(s.packfile[:len(s.packfile)-sha1.Size])
	if !bytes.Equal(expected, actual[:]) {
		return [sha1.Size]byte{}, fmt.Errorf("checksum mismatch: expected %x, got %x", expected, actual)
	}
	return actual, nil
}

// Reset initializes the Scanner with the given packfile data.
func (s *Scanner) Reset(packfile []byte) {
	s.packfile = packfile
	s.offset = 0
	s.cache.Purge()
}

// NewScanner creates a new Scanner for the given packfile data. The packfile data is not copied, so the caller must ensure it remains valid for the lifetime of the Scanner.
func NewScanner(lruSize int) (*Scanner, error) {
	cache, err := lru.New[int, cacheEntry](lruSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}
	dc, err := libdeflate.NewDecompressor()
	if err != nil {
		return nil, fmt.Errorf("failed to create decompressor: %w", err)
	}
	attachAutoClose(dc)
	return &Scanner{decompressor: dc, cache: cache}, nil
}
