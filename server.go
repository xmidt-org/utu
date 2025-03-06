// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"
)

type ServerIn struct {
	fx.In

	Logger       *zap.Logger
	CLI          CLI
	ListenConfig *net.ListenConfig
	KeyHandler   *KeyHandler
	IssueHandler *IssueHandler

	Lifecycle  fx.Lifecycle
	Shutdowner fx.Shutdowner
}

func NewServer(in ServerIn) (s *http.Server, err error) {
	s = &http.Server{
		Addr:              in.CLI.Address,
		ReadHeaderTimeout: 2 * time.Second,
	}

	mux := http.NewServeMux()
	mux.Handle("/key", in.KeyHandler)
	mux.Handle("/issue", in.IssueHandler)
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
							zap.String("key", fmt.Sprintf("http://%s/key", s.Addr)),
							zap.String("issue", fmt.Sprintf("http://%s/issue", s.Addr)),
						)

						serveErr := s.Serve(l)
						if serveErr != nil {
							in.Logger.Error("unable to start server", zap.Error(serveErr))
						}
					}()
				}

				if err != nil {
					in.Logger.Error("unable to start server", zap.Error(err))
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
