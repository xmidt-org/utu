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
	)
}
