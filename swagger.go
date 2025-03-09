// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"embed"
	"net/http"

	"go.uber.org/fx"
)

//go:embed swagger
var swaggerFS embed.FS

func NewSwaggerHandler(swaggerFS embed.FS) http.Handler {
	return http.FileServerFS(swaggerFS)
}

func ProvideSwagger() fx.Option {
	return fx.Options(
		fx.Supply(swaggerFS),
		fx.Provide(
			fx.Annotate(
				NewSwaggerHandler,
				fx.ResultTags(`name:"swaggerHandler"`),
			),
		),
	)
}
