package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type claim struct {
	name  string
	value any
}

func (c claim) String() string {
	return fmt.Sprintf("%s=%v", c.name, c.value)
}

type claims []claim

func (cs claims) MarshalLogArray(ae zapcore.ArrayEncoder) error {
	for _, c := range cs {
		ae.AppendString(c.String())
	}

	return nil
}

type Issuer struct {
	logger *zap.Logger
	random io.Reader
	now    func() time.Time

	iss     string
	sub     string
	aud     []string
	claims  claims
	expires time.Duration
}

func NewIssuer(l *zap.Logger, cli CLI) (i *Issuer, err error) {
	i = &Issuer{
		logger:  l,
		random:  rand.Reader,
		now:     time.Now,
		iss:     cli.Issuer,
		sub:     cli.Subject,
		aud:     cli.Audience,
		expires: cli.Expires,
	}

	i.claims = make(claims, 0, len(cli.Claims))
	for k, v := range cli.Claims {
		i.claims = append(i.claims, claim{name: k, value: v})
	}

	i.logger.Info("issuer",
		zap.String("iss", i.iss),
		zap.String("sub", i.sub),
		zap.Strings("aud", i.aud),
		zap.Duration("expires", i.expires),
		zap.Any("claims", i.claims),
	)

	return
}

func (i *Issuer) generateID() (jti string, err error) {
	var buf [32]byte
	_, err = io.ReadFull(i.random, buf[:])
	if err == nil {
		jti = base64.RawURLEncoding.EncodeToString(buf[:])
	}

	return
}

func (i *Issuer) buildToken(b *jwt.Builder) {
	now := i.now().UTC()

	for _, c := range i.claims {
		b.Claim(c.name, c.value)
	}

	b.Issuer(i.iss).
		Audience(i.aud).
		Subject(i.sub).
		IssuedAt(now).
		Expiration(now.Add(i.expires))
}

func (i *Issuer) Issue() (t jwt.Token, err error) {
	var (
		jti string
		b   *jwt.Builder
	)

	jti, err = i.generateID()
	if err == nil {
		b = jwt.NewBuilder().JwtID(jti)
		i.buildToken(b)
		t, err = b.Build()
	}

	return
}

type IssueHandler struct {
	logger *zap.Logger
	issuer *Issuer
	signer *Signer
}

func NewIssueHandler(l *zap.Logger, issuer *Issuer, signer *Signer) *IssueHandler {
	return &IssueHandler{
		logger: l,
		issuer: issuer,
		signer: signer,
	}
}

func (ih *IssueHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	var signed []byte
	t, err := ih.issuer.Issue()
	if err == nil {
		signed, err = ih.signer.Sign(t)
	}

	if err == nil {
		response.Header().Set("Content-Type", "application/jwt")
		response.Write(signed)
	} else {
		ih.logger.Error("unable to issue token", zap.Error(err))
		response.Header().Set("Content-Type", "text/plain;charset=utf-8")
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(err.Error()))
	}
}

func ProvideIssuer() fx.Option {
	return fx.Provide(
		NewIssuer,
		NewIssueHandler,
	)
}
