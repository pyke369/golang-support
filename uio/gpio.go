//go:build !linux

package uio

import (
	"errors"
)

type GPIO struct{}

type GPIOLINE struct{}

func GPIOCount() int {
	return 0
}

func GPIOOpen(index ...int) (gpio *GPIO, err error) {
	return nil, errors.ErrUnsupported
}

func (g *GPIO) Name() string {
	return "unsupported"
}

func (g *GPIO) Label() string {
	return "unsupported"
}

func (g *GPIO) Lines() (lines []*GPIOLINE) {
	return []*GPIOLINE{}
}
