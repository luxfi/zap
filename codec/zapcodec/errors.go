// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapcodec

import "errors"

// Sentinel errors — same surface as the historical luxfi/codec
// sentinels so consumers asserting via errors.Is on the post-rename
// values get equivalent behaviour after the module move.
var (
	ErrUnsupportedType           = errors.New("zapcodec: unsupported type")
	ErrMaxSliceLenExceeded       = errors.New("zapcodec: max slice length exceeded")
	ErrDoesNotImplementInterface = errors.New("zapcodec: does not implement interface")
	ErrUnexportedField           = errors.New("zapcodec: unexported field")
	ErrMarshalZeroLength         = errors.New("zapcodec: can't marshal zero length value")
	ErrUnmarshalZeroLength       = errors.New("zapcodec: can't unmarshal zero length value")
	ErrMarshalNil                = errors.New("zapcodec: can't marshal nil pointer")
	ErrUnmarshalNil              = errors.New("zapcodec: can't unmarshal into nil")
	ErrDuplicateType             = errors.New("zapcodec: duplicate type registration")
)
