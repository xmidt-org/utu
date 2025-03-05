package main

import (
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Signer struct {
	logger *zap.Logger
	key    *Key
}

func NewSigner(l *zap.Logger, key *Key, cli CLI) (s *Signer, err error) {
	s = &Signer{
		logger: l,
		key:    key,
	}

	return
}

func (s *Signer) Sign(t jwt.Token) ([]byte, error) {
	return jwt.Sign(
		t,
		jwt.WithKey(
			s.key.Alg(),
			s.key.Current().Key,
		),
	)
}

func ProvideSigner() fx.Option {
	return fx.Provide(
		NewSigner,
	)
}
