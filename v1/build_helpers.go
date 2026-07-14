// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1

import "github.com/luxfi/zap"

// SetterFrom adapts a raw v1 ([github.com/luxfi/zap]) ObjectBuilder +
// Builder pair into a typed Setter[S]. It is the bridge the hand-rolled
// codegen fast path uses to reach the typed list/variable-length writers
// (WriteList, WriteString, WriteBytes) without abandoning the
// straight-line `b.StartObject` construction that inlines at the call
// site. The (ob, b) must be the pair returned by the same StartObject —
// passing a mismatched pair is a programming error.
func SetterFrom[S Schema](ob zap.ObjectBuilder, b *zap.Builder) Setter[S] {
	return Setter[S]{ob: ob, b: b}
}

// WriteString writes a variable-length UTF-8 string field to the object
// tail and stores its {relOffset, length} pointer at byteOffset in the
// fixed payload. The typed peer of [zap.ObjectBuilder.SetText] for the
// Setter-based build path. Read it back with the generated string
// accessor (which calls v1's zero-copy Object.Text).
func WriteString[S Schema](s Setter[S], byteOffset uint32, v string) {
	ob, _ := s.raw()
	ob.SetText(int(byteOffset), v)
}

// WriteBytes writes a variable-length byte slice to the object tail and
// stores its {relOffset, length} pointer at byteOffset. The typed peer
// of [zap.ObjectBuilder.SetBytes]. Zero-copy on read via Object.Bytes.
func WriteBytes[S Schema](s Setter[S], byteOffset uint32, v []byte) {
	ob, _ := s.raw()
	ob.SetBytes(int(byteOffset), v)
}
