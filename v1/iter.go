// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1

import "iter"

// This file provides a minimum useful set of [iter.Seq] combinators
// for ZAP lists. The stdlib does not yet ship Filter/Map for Seqs in
// Go 1.23; we add only what we need and nothing more. Composition,
// not inheritance: every combinator returns an iter.Seq that the next
// combinator can consume.

// Take returns an iter.Seq yielding at most n elements from src. If
// src yields fewer than n, all of them are passed through; if more,
// the iteration stops after n.
//
// Constant memory: Take does not buffer. It counts and short-circuits.
func Take[T any](src iter.Seq[T], n int) iter.Seq[T] {
	return func(yield func(T) bool) {
		if n <= 0 {
			return
		}
		i := 0
		for v := range src {
			if !yield(v) {
				return
			}
			i++
			if i >= n {
				return
			}
		}
	}
}

// Filter returns an iter.Seq yielding only those elements of src for
// which pred returns true. Constant memory; one allocation per call
// (the closure), zero per element.
func Filter[T any](src iter.Seq[T], pred func(T) bool) iter.Seq[T] {
	return func(yield func(T) bool) {
		for v := range src {
			if pred(v) && !yield(v) {
				return
			}
		}
	}
}

// Map returns an iter.Seq[U] obtained by applying f to each element of
// src. Constant memory per element.
func Map[T, U any](src iter.Seq[T], f func(T) U) iter.Seq[U] {
	return func(yield func(U) bool) {
		for v := range src {
			if !yield(f(v)) {
				return
			}
		}
	}
}

// Count returns the number of elements yielded by src. Drains the
// sequence — do not call on infinite sequences.
func Count[T any](src iter.Seq[T]) int {
	n := 0
	for range src {
		n++
	}
	return n
}

// Collect drains src into a freshly allocated slice. Useful in tests
// where the caller wants to assert on the materialized list; not
// recommended in the hot path because it defeats the zero-copy
// property of [List].
func Collect[T any](src iter.Seq[T]) []T {
	out := make([]T, 0)
	for v := range src {
		out = append(out, v)
	}
	return out
}
