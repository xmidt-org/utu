// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"sync/atomic"

	"go.uber.org/fx"
)

var (
	ErrNoCurrentKey = errors.New("the current key has not been initialized")
)

// CurrentKey is a simple, atomic access point for the current signing key.
type CurrentKey struct {
	current atomic.Value
}

func (ck *CurrentKey) Load() (k Key, err error) {
	var ok bool
	k, ok = ck.current.Load().(Key)
	if !ok {
		err = ErrNoCurrentKey
	}

	return
}

func (ck *CurrentKey) Store(k Key) {
	ck.current.Store(k)
}

func ProvideCurrentKey() fx.Option {
	return fx.Supply(new(CurrentKey))
}
