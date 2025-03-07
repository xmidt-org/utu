// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Signer struct {
	logger *zap.Logger
	keys   *Keys
	typ    string
}

func NewSigner(l *zap.Logger, keys *Keys, cli CLI) (s *Signer, err error) {
	s = &Signer{
		logger: l,
		keys:   keys,
		typ:    cli.Type,
	}

	s.logger.Info("signer",
		zap.String("typ", s.typ),
	)

	return
}

func (s *Signer) buildProtectedHeaders(currentKey *GeneratedKey) (h jws.Headers) {
	h = jws.NewHeaders()
	h.Set(jws.KeyIDKey, currentKey.KID())
	h.Set(jws.TypeKey, s.typ)
	return
}

func (s *Signer) Sign(t jwt.Token) ([]byte, error) {
	currentKey := s.keys.Current()
	h := s.buildProtectedHeaders(currentKey)

	return jwt.Sign(
		t,
		currentKey.WithSigningKey(
			jws.WithProtectedHeaders(h),
		),
	)
}

func ProvideSigner() fx.Option {
	return fx.Provide(
		NewSigner,
	)
}
