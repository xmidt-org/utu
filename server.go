// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"
)

type ServerIn struct {
	fx.In

	Logger         *zap.Logger
	CLI            CLI
	ListenConfig   *net.ListenConfig
	KeyHandler     *KeyHandler
	KeysHandler    *KeysHandler
	IssueHandler   *IssueHandler
	SignHandler    *SignHandler
	SwaggerHandler http.Handler `name:"swaggerHandler"`

	Lifecycle  fx.Lifecycle
	Shutdowner fx.Shutdowner
}

func NewServer(in ServerIn) (s *http.Server, err error) {
	s = &http.Server{
		Addr:              in.CLI.Address,
		ReadHeaderTimeout: 2 * time.Second,
	}

	mux := http.NewServeMux()
	mux.Handle("GET /keys", in.KeysHandler)
	mux.Handle("GET /key", in.KeyHandler)
	mux.Handle("GET /key/{kid}", in.KeyHandler)
	mux.Handle("GET /issue", in.IssueHandler)
	mux.Handle("PUT /sign", in.SignHandler)
	mux.Handle("GET /swagger/", in.SwaggerHandler)
	s.Handler = mux

	in.Lifecycle.Append(
		fx.StartStopHook(
			func(ctx context.Context) (err error) {
				var l net.Listener
				l, err = in.ListenConfig.Listen(ctx, in.CLI.Network, in.CLI.Address)
				if err == nil {
					s.Addr = l.Addr().String()
					go func() {
						defer in.Shutdowner.Shutdown()

						in.Logger.Info(
							"starting server",
							zap.String("address", s.Addr),
							zap.Any(
								"endpoints",
								map[string]string{
									"key":   fmt.Sprintf("http://%s/key", s.Addr),
									"keys":  fmt.Sprintf("http://%s/keys", s.Addr),
									"issue": fmt.Sprintf("http://%s/issue", s.Addr),
									"sign":  fmt.Sprintf("http://%s/sign", s.Addr),
								},
							),
						)

						serveErr := s.Serve(l)
						if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
							in.Logger.Error("unable to start server", zap.Error(serveErr))
						}
					}()
				}

				if err != nil {
					in.Logger.Error("unable to start listener", zap.Error(err))
				}

				return
			},
			s.Shutdown,
		),
	)

	return
}

func ProvideServer() fx.Option {
	return fx.Options(
		fx.Provide(
			func() *net.ListenConfig {
				return new(net.ListenConfig)
			},
			NewServer,
		),
		fx.Invoke(
			// force the server to start
			func(*http.Server) {},
		),
	)
}
