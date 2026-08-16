//go:build windows

package net

import (
	"errors"
)

func reuseAddr(handle uintptr) error {
	return errors.ErrUnsupported
}

func reusePort(handle uintptr) error {
	return errors.ErrUnsupported
}
