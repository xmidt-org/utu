// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type errorHandler struct{}

func (errorHandler) HandleError(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
}

func run(args []string, options ...kong.Option) {
	cli, kctx, err := NewCLI(args, options...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	app := fx.New(
		fx.Supply(cli, kctx),
		ProvideLogging(),
		fx.Module(
			"keys",
			fx.Decorate(
				func(l *zap.Logger) *zap.Logger {
					return l.Named("keys")
				},
			),
			ProvideCurrentKey(),
			ProvideKeyStore(),
			ProvideIDGenerator(),
			ProvideKeyGenerator(),
			ProvideSigner(),
			ProvideIssuer(),
			ProvideRotator(),
		),
		fx.Module(
			"http",
			fx.Decorate(
				func(l *zap.Logger) *zap.Logger {
					return l.Named("http")
				},
			),
			ProvideServer(),
		),
		fx.ErrorHook(errorHandler{}),
	)

	app.Run()
}

func main() {
	run(os.Args[1:])
}
