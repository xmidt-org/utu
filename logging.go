// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
)

// ProvideLogging sets up the main zap.Logger and configures fx to use it.
func ProvideLogging() fx.Option {
	return fx.Options(
		fx.Provide(
			func(cli CLI) (*zap.Logger, error) {
				cfg := zap.NewDevelopmentConfig()
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
