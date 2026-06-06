// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codec

// Size constants for binary packing
const (
	// ByteLen is the number of bytes per byte
	ByteLen = 1
	// ShortLen is the number of bytes per short
	ShortLen = 2
	// VersionSize is the number of bytes used for codec version
	VersionSize = ShortLen
	// IntLen is the number of bytes per int
	IntLen = 4
	// LongLen is the number of bytes per long
	LongLen = 8
	// BoolLen is the number of bytes per bool
	BoolLen = 1
	// IPLen is the number of bytes per IP (16 bytes + 2 for port)
	IPLen = 16 + ShortLen
)

// StringLen returns the packed length of a string (2-byte length prefix + string bytes)
func StringLen(str string) int {
	return ShortLen + len(str)
}

// Errs collects errors during a series of operations.
// It stores only the first error encountered.
type Errs struct {
	Err error
}

// Errored returns true if an error has been recorded.
func (errs *Errs) Errored() bool {
	return errs.Err != nil
}

// Add records the first non-nil error.
func (errs *Errs) Add(errors ...error) {
	if errs.Err == nil {
		for _, err := range errors {
			if err != nil {
				errs.Err = err
				break
			}
		}
	}
}
