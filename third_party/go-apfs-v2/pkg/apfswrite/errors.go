// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import "errors"

var (
	errDeviceTooBig   = errors.New("apfswrite: device is too big")
	errIPPoolTooBig   = errors.New("apfswrite: internal pool too big for the main device")
	errCabUnsupported = errors.New("apfswrite: container too large (CIB address block layer not supported)")
	errFileDataTooBig = errors.New("apfswrite: file data and metadata do not fit in the container")
)
