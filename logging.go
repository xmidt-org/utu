// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// ProvideLogging sets up the main zap.Logger and configures fx to use it.
func ProvideLogging() fx.Option {
	return fx.Options(
		fx.Provide(
			zap.NewDevelopment,
		),
		fx.NopLogger,
		/*
			fx.WithLogger(
				func(l *zap.Logger) fxevent.Logger {
					return &fxevent.ZapLogger{
						Logger: l,
					}
				},
			),
		*/
	)
}
