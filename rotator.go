// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"sync"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"
)

// RotatorIn defines the dependencies necessary to create a Rotator.
type RotatorIn struct {
	fx.In

	Logger    *zap.Logger
	Keys      *Keys
	CLI       CLI
	Lifecycle fx.Lifecycle
}

// Rotator manages a set of background processes for key rotation.
//
// The current key in a Keys is rotated according to the configured
// rotation interval. The previous current key will be deleted after
// the token expire time plus a grace period elapses.
type Rotator struct {
	logger *zap.Logger
	keys   *Keys
	rotate time.Duration
	grace  time.Duration

	lock   sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

func NewRotator(in RotatorIn) (r *Rotator) {
	r = &Rotator{
		logger: in.Logger,
		keys:   in.Keys,
		rotate: in.CLI.KeyRotate,
		grace:  in.CLI.Expires + time.Minute,
	}

	r.logger.Info("rotator",
		zap.Duration("rotate", r.rotate),
		zap.Duration("grace", r.grace),
	)

	in.Lifecycle.Append(
		fx.StartStopHook(
			r.Start,
			r.Stop,
		),
	)

	return
}

// rotateTask represents the background goroutine that rotates keys.
type rotateTask struct {
	ctx    context.Context
	logger *zap.Logger
	keys   *Keys
	rotate <-chan time.Time
	stop   func()
	grace  func() (<-chan time.Time, func() bool)
}

// cleanup is a goroutine that waits out the grace period to delete a key.
func (rt rotateTask) cleanup(kid string, ch <-chan time.Time, stop func() bool) {
	defer stop()

	select {
	case <-rt.ctx.Done():
		// if we're explicitly stopped, leave the key alone
		return

	case <-ch:
		rt.keys.Delete(kid)
	}
}

// run is a goroutine that rotates keys in the background.
func (rt rotateTask) run() {
	defer rt.stop()

	for {
		select {
		case <-rt.ctx.Done():
			return

		case <-rt.rotate:
			if old, _, err := rt.keys.Rotate(); err == nil {
				ch, stop := rt.grace()
				go rt.cleanup(old.KID(), ch, stop)
			} else {
				rt.logger.Error("unable to rotate key", zap.Error(err))
			}
		}
	}
}

// Start starts the background goroutine to rotate keys. In addition, when
// a key is rotated, the old current key is deleted after the token expires period
// (plus a small grace period) expires.
//
// This method is idempotent.
func (r *Rotator) Start() {
	defer r.lock.Unlock()
	r.lock.Lock()

	if r.cancel == nil {
		r.logger.Info("starting key rotation task", zap.Duration("interval", r.rotate))
		r.ctx, r.cancel = context.WithCancel(context.Background())
		ticker := time.NewTicker(r.rotate)
		go rotateTask{
			ctx:    r.ctx,
			logger: r.logger,
			keys:   r.keys,
			rotate: ticker.C,
			stop:   ticker.Stop,
			grace: func() (<-chan time.Time, func() bool) {
				timer := time.NewTimer(r.grace)
				return timer.C, timer.Stop
			},
		}.run()
	}
}

// Stop stops all background processes started by this Rotator. This method is idempotent.
func (r *Rotator) Stop() {
	defer r.lock.Unlock()
	r.lock.Lock()

	if r.cancel != nil {
		r.cancel()
		r.ctx, r.cancel = nil, nil
	}
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
