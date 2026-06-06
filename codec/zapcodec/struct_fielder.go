// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapcodec

import (
	"fmt"
	"reflect"
	"sync"
)

// DefaultTagName is the struct tag this codec honours. Same value as
// the legacy luxfi/codec linearcodec used ("serialize") — the post-
// extraction wire format is byte-identical to what consumers expect.
const DefaultTagName = "serialize"

// tagValue is the value the struct tag must have for a field to be
// serialised — e.g. `serialize:"true"`.
const tagValue = "true"

// structFielder discovers serializable fields in a struct via tag
// inspection. Cached per-type — the cache is keyed by reflect.Type
// pointer so it's stable across calls.
type structFielder struct {
	lock sync.RWMutex

	// tags are the struct-tag names this fielder honours. A field is
	// serialised if ANY of the listed tags has value "true".
	tags []string

	// serializedFieldIndices caches the per-type field-index slice.
	serializedFieldIndices map[reflect.Type][]int
}

// newStructFielder constructs a fresh structFielder over the supplied
// tag names. Concurrency-safe after construction.
func newStructFielder(tagNames []string) *structFielder {
	return &structFielder{
		tags:                   tagNames,
		serializedFieldIndices: make(map[reflect.Type][]int),
	}
}

// GetSerializedFields returns the indices of fields in t that have
// any of the structFielder's tags set to "true". Caches per-type.
// Returns ErrUnexportedField if a tagged field is un-exported (which
// would prevent reflect-based marshalling).
func (s *structFielder) GetSerializedFields(t reflect.Type) ([]int, error) {
	if cached, ok := s.getCached(t); ok {
		return cached, nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	numFields := t.NumField()
	serializedFields := make([]int, 0, numFields)
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		var capture bool
		for _, tag := range s.tags {
			if field.Tag.Get(tag) == tagValue {
				capture = true
				break
			}
		}
		if !capture {
			continue
		}
		if !field.IsExported() {
			return nil, fmt.Errorf("can not marshal %w: %s", ErrUnexportedField, field.Name)
		}
		serializedFields = append(serializedFields, i)
	}
	s.serializedFieldIndices[t] = serializedFields
	return serializedFields, nil
}

// getCached returns the cached field-index slice for t. The bool
// distinguishes "cached as empty" from "not cached".
func (s *structFielder) getCached(t reflect.Type) ([]int, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	cached, ok := s.serializedFieldIndices[t]
	return cached, ok
}
