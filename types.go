package fastpack

import (
	"crypto/sha1"
	"fmt"
)

// ObjectType is the type of an object within a packfile.
type ObjectType int8

const (
	InvalidObject ObjectType = 0
	CommitObject  ObjectType = 1
	TreeObject    ObjectType = 2
	BlobObject    ObjectType = 3
	TagObject     ObjectType = 4
	// 5 reserved for future expansion
	OFSDeltaObject ObjectType = 6
	REFDeltaObject ObjectType = 7
)

// Valid returns true if the ObjectType is a valid Git object type.
func (ot ObjectType) Valid() bool {
	switch ot {
	case CommitObject, TreeObject, BlobObject, TagObject, OFSDeltaObject, REFDeltaObject:
		return true
	}
	return false
}

// String returns the string representation of the ObjectType.
func (ot ObjectType) String() string {
	switch ot {
	case InvalidObject:
		return "invalid"
	case CommitObject:
		return "commit"
	case TreeObject:
		return "tree"
	case BlobObject:
		return "blob"
	case TagObject:
		return "tag"
	case OFSDeltaObject:
		return "ofs-delta"
	case REFDeltaObject:
		return "ref-delta"
	default:
		return "unknown"
	}
}

// OID returns the git OID for a given ObjectType and content
func OID(ot ObjectType, b []byte) [sha1.Size]byte {
	return sha1.Sum(append(fmt.Appendf(nil, "%s %d\x00", ot.String(), len(b)), b...))
}
