package uio

import (
	"errors"

	"github.com/pyke369/golang-support/ustr"
)

var unsupported = ustr.Wrap(errors.ErrUnsupported, "uio")
