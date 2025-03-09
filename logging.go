// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// KeyMarshaler is a zap ObjectMarshaler for Keys.
type KeyMarshaler struct {
	Key
}

func (km KeyMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("kid", km.KID)
	enc.AddTime("expires", km.Expires)
	return nil
}

// KeyField emits a zap log field for the given key.
func KeyField(name string, key Key) zap.Field {
	return zap.Object(name, KeyMarshaler{key})
}

// ProvideLogging sets up the main zap.Logger and configures fx to use it.
func ProvideLogging() fx.Option {
	return fx.Options(
		fx.Provide(
			func(cli CLI) (*zap.Logger, error) {
				cfg := zap.NewDevelopmentConfig()
				cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
					zapcore.RFC3339NanoTimeEncoder(t.UTC(), enc)
				}

				if cli.Debug {
					cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
				} else {
					cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
				}

				return cfg.Build()
			},
		),
		fx.WithLogger(
			func(l *zap.Logger, cli CLI) fxevent.Logger {
				var startup *zap.Logger
				if cli.Debug {
					startup = l.Named("startup")
				} else {
					startup = zap.NewNop()
				}

				return &fxevent.ZapLogger{
					Logger: startup,
				}
			},
		),
	)
}
