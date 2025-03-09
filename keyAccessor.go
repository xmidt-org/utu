// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"sync/atomic"

	"go.uber.org/fx"
)

var (
	// ErrNoCurrentKey is returned by KeyAccessor.Load to indicate that no current
	// key has been set.
	ErrNoCurrentKey = errors.New("the current key has not been initialized")
)

// KeyAccessor is a simple, atomic access point for the current signing key.
type KeyAccessor struct {
	current atomic.Value
}

// Load returns the current signing key. If no signing key has been set yet,
// this method returns ErrNoCurrentKey.
func (ck *KeyAccessor) Load() (k Key, err error) {
	var ok bool
	k, ok = ck.current.Load().(Key)
	if !ok {
		err = ErrNoCurrentKey
	}

	return
}

// Store updates the current key.
func (ck *KeyAccessor) Store(k Key) {
	ck.current.Store(k)
}

func ProvideKeyAccessor() fx.Option {
	return fx.Supply(new(KeyAccessor))
}
