// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Signer struct {
	logger      *zap.Logger
	keyAccessor *KeyAccessor
	typ         string
}

func NewSigner(l *zap.Logger, keyAccessor *KeyAccessor, cli CLI) (s *Signer, err error) {
	s = &Signer{
		logger:      l,
		keyAccessor: keyAccessor,
		typ:         cli.Type,
	}

	s.logger.Info("signer",
		zap.String("typ", s.typ),
	)

	return
}

// SignToken returns the compact serialization of the given token signed with
// the current signing key.
func (s *Signer) SignToken(t jwt.Token) (signed []byte, err error) {
	var currentKey Key
	currentKey, err = s.keyAccessor.Load()

	if err == nil {
		h := jws.NewHeaders()
		h.Set(jws.KeyIDKey, currentKey.KID)
		h.Set(jws.TypeKey, s.typ)

		signed, err = jwt.Sign(
			t,
			jwt.WithKey(
				currentKey.Alg,
				currentKey.Key,
				jws.WithProtectedHeaders(h),
			),
		)
	}

	return
}

func (s *Signer) ctyOf(contentType string) string {
	parts := strings.Split(contentType, "/")
	if len(parts) == 2 && parts[0] == "application" {
		return parts[1]
	} else {
		return contentType
	}
}

// SignPayload returns the compact serialization of the given payload signed
// with the current signing key. The contentType value is used to determine the
// typ attribute in the protected header.
func (s *Signer) SignPayload(contentType string, p []byte) (signed []byte, err error) {
	var currentKey Key
	currentKey, err = s.keyAccessor.Load()

	if err == nil {
		h := jws.NewHeaders()
		h.Set(jws.KeyIDKey, currentKey.KID)
		if len(contentType) > 0 {
			h.Set(jws.ContentTypeKey, s.ctyOf(contentType))
		}

		signed, err = jws.Sign(
			p,
			jws.WithKey(
				currentKey.Alg,
				currentKey.Key,
				jws.WithProtectedHeaders(h),
			),
		)
	}

	return
}

// SignHandler accepts an arbitrary payload and signs it with the current
// signing key.
type SignHandler struct {
	logger *zap.Logger
	signer *Signer
}

func NewSignHandler(l *zap.Logger, s *Signer) *SignHandler {
	return &SignHandler{
		logger: l,
		signer: s,
	}
}

func (sh *SignHandler) readPayload(request *http.Request) (payload []byte, err error) {
	if request.ContentLength >= 0 {
		payload = make([]byte, request.ContentLength)
		_, err = io.ReadFull(request.Body, payload)
	} else {
		payload, err = io.ReadAll(request.Body)
	}

	return
}

// ServeHTTP produces a signed JWS.  The cty header attribute is derived from the Content-Type
// header, and will not be set if not Content-Type header is set.
func (sh *SignHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	payload, err := sh.readPayload(request)
	if err != nil {
		// ignore read errors
		return
	}

	var jws []byte
	if jws, err = sh.signer.SignPayload(request.Header.Get("Content-Type"), payload); err == nil {
		response.Write(jws)
	} else {
		sh.logger.Error("unable to sign payload", zap.Error(err))
		response.WriteHeader(http.StatusInternalServerError)
	}
}

func ProvideSigner() fx.Option {
	return fx.Provide(
		NewSigner,
		NewSignHandler,
	)
}
