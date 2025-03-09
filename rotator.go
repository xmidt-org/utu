// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	// ErrRotatorStarted is returned by Rotator.Start to indicate that Start has already been called.
	ErrRotatorStarted = errors.New("the key rotator has already been started")

	// ErrRotatorStopped is returned by Rotator.Stop to indicate that Stop has already been called.
	ErrRotatorStopped = errors.New("the key rotator has already been stopped")
)

// RotatorIn defines the dependencies necessary to create a Rotator.
type RotatorIn struct {
	fx.In

	Logger       *zap.Logger
	KeyGenerator *KeyGenerator
	CurrentKey   *CurrentKey
	KeyStore     KeyStore
	CLI          CLI
	Lifecycle    fx.Lifecycle
}

// Rotator manages a set of background processes for key rotation.
//
// The current key in a Keys is rotated according to the configured
// rotation interval. The previous current key will be deleted after
// the token expire time plus a grace period elapses.
//
// Rotated keys will expire based on not only the rotation period but
// also the token expires.  The basic formula for a key's expire is
// key rotation + token expires + 1m grace period. This allows for tokens
// that are still being used to be verified by the key used to sign them.
type Rotator struct {
	logger       *zap.Logger
	keyGenerator *KeyGenerator
	currentKey   *CurrentKey
	keyStore     KeyStore
	rotate       time.Duration

	lock   sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

func NewRotator(in RotatorIn) (r *Rotator) {
	r = &Rotator{
		logger:       in.Logger,
		keyGenerator: in.KeyGenerator,
		currentKey:   in.CurrentKey,
		keyStore:     in.KeyStore,
		rotate:       in.CLI.KeyRotate,
	}

	r.logger.Info("rotator",
		zap.Duration("rotate", r.rotate),
	)

	in.Lifecycle.Append(
		fx.StartStopHook(
			r.Start,
			r.Stop,
		),
	)

	return
}

// unsafeStoreKey handles storing a key in the KeyStore and then, if
// no error occurred, updating the CurrentKey. This method is not atomic,
// and must be executed under the lock.
func (r *Rotator) unsafeStoreKey(k Key) (err error) {
	var pk Key
	pk, err = k.PublicKey()
	if err == nil {
		// store the public portion of the key
		err = r.keyStore.Store(pk)
	}

	if err == nil {
		// stash the private key in our access point
		r.currentKey.Store(k)
	}

	return
}

// Rotate generates a new key, updates the KeyStore, and then updates the CurrentKey.
// This method returns the new current key. If this method returns any error, the key
// was not rotated.
func (r *Rotator) Rotate() (k Key, err error) {
	k, err = r.keyGenerator.Generate()
	if err == nil {
		defer r.lock.Unlock()
		r.lock.Lock()
		err = r.unsafeStoreKey(k)
	}

	return
}

// rotateTask represents the background goroutine that rotates keys.
type rotateTask struct {
	ctx    context.Context
	logger *zap.Logger
	rotate func() (Key, error)
	ch     <-chan time.Time
	stop   func()
}

// run is a goroutine that rotates keys in the background.
func (rt rotateTask) run() {
	defer rt.stop()

	for {
		select {
		case <-rt.ctx.Done():
			return

		case <-rt.ch:
			if newKey, err := rt.rotate(); err == nil {
				rt.logger.Info("rotated key", KeyField("key", newKey))
			} else {
				rt.logger.Error("unable to rotate key", zap.Error(err))
			}

			// TODO: handle cleanup
		}
	}
}

// Start immediately rotates the current key and then starts a background goroutine to
// rotate the key on the configured interval. This method is idempotent.
func (r *Rotator) Start() (err error) {
	defer r.lock.Unlock()
	r.lock.Lock()

	if r.cancel != nil {
		// already started
		err = ErrRotatorStarted
	}

	var initialKey Key
	if err == nil {
		// immediately rotate the key
		initialKey, err = r.keyGenerator.Generate()
		err = r.unsafeStoreKey(initialKey)
	}

	if err == nil {
		r.logger.Info("initial key", KeyField("key", initialKey))
		r.logger.Info("starting key rotation task", zap.Duration("interval", r.rotate))
		r.ctx, r.cancel = context.WithCancel(context.Background())
		ticker := time.NewTicker(r.rotate)
		go rotateTask{
			ctx:    r.ctx,
			logger: r.logger,
			rotate: r.Rotate,
			ch:     ticker.C,
			stop:   ticker.Stop,
		}.run()
	}

	return
}

// Stop stops all background processes started by this Rotator. This method is idempotent.
func (r *Rotator) Stop() (err error) {
	defer r.lock.Unlock()
	r.lock.Lock()

	if r.cancel != nil {
		r.cancel()
		r.ctx, r.cancel = nil, nil
	} else {
		err = ErrRotatorStopped
	}

	return
}

func ProvideRotator() fx.Option {
	return fx.Options(
		fx.Provide(
			NewRotator,
		),
		fx.Invoke(
			// ensure the Rotator starts
			func(*Rotator) {},
		),
	)
}
