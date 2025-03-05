package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// MarshaledKey holds premarshaled information for a generated key.
type MarshaledKey struct {
	// Public is a premarshaled Public key.
	Public []byte

	// Set is a premarshaled JWK set that contains only the public key.
	Set []byte
}

// GeneratedKey holds the various objects related to a generated JWK.
type GeneratedKey struct {
	// KID is the unique, URL-safe identifier for this key.
	KID string

	// Key is the actual generated key.  This will always be a PRIVATE key.
	Key jwk.Key

	// Marshaled holds the premarshaled key material for this key.
	Marshaled MarshaledKey
}

// Key holds the current key for signing and verification.
type Key struct {
	logger  *zap.Logger
	random  io.Reader
	current atomic.Value

	alg   jwa.KeyAlgorithm
	kty   jwa.KeyType
	bits  int
	curve elliptic.Curve
}

func NewKey(logger *zap.Logger, cli CLI) (k *Key, err error) {
	k = &Key{
		logger: logger,
		random: rand.Reader,
		bits:   cli.KeySize,
	}

	switch {
	case cli.KeyType == "EC" && cli.KeyCurve == "P-256":
		k.kty = jwa.EC()
		k.curve = elliptic.P256()
		k.alg = jwa.ES256()

	case cli.KeyType == "EC" && cli.KeyCurve == "P-384":
		k.kty = jwa.EC()
		k.curve = elliptic.P384()
		k.alg = jwa.ES384()

	case cli.KeyType == "EC" && cli.KeyCurve == "P-521":
		k.kty = jwa.EC()
		k.curve = elliptic.P521()
		k.alg = jwa.ES512()

	case cli.KeyType == "RSA" && cli.KeySize > 0:
		k.kty = jwa.RSA()
		k.bits = cli.KeySize
		k.alg = jwa.RS256()

	default:
		err = fmt.Errorf("unsupported key parameters: type=%s, size=%d, curve=%s", cli.KeyType, cli.KeySize, cli.KeyCurve)
	}

	if err == nil {
		_, err = k.updateKey()
	}

	return
}

// generatedKeyID creates a URL-safe, random kid from the configured
// source of randomness.
func (k *Key) generateKeyID() (kid string, err error) {
	var buf [16]byte
	_, err = io.ReadFull(k.random, buf[:])
	if err == nil {
		kid = base64.RawURLEncoding.EncodeToString(buf[:])
	}

	return
}

// generateKey creates a new key of the configured type.
func (k *Key) generateKey(kid string) (key jwk.Key, err error) {
	var raw any

	switch {
	case k.kty == jwa.RSA():
		raw, err = rsa.GenerateKey(k.random, k.bits)

	case k.kty == jwa.EC():
		raw, err = ecdsa.GenerateKey(k.curve, k.random)

	default:
		err = fmt.Errorf("unsupported key type: %s", k.kty)
	}

	if err == nil {
		key, err = jwk.Import(raw)
	}

	if err == nil {
		key.Set(jwk.KeyUsageKey, jwk.ForSignature)
		key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify})
		key.Set(jwk.KeyIDKey, kid)
	}

	return
}

// updateKey updates the current key in use for signing and verification.
// It stores this information internally, and returns the updated currentKey.
func (k *Key) updateKey() (updated GeneratedKey, err error) {
	updated.KID, err = k.generateKeyID()
	if err == nil {
		updated.Key, err = k.generateKey(updated.KID)
	}

	var publicKey jwk.Key
	if err == nil {
		publicKey, err = updated.Key.PublicKey()
	}

	if err == nil {
		updated.Marshaled.Public, err = json.Marshal(publicKey)
	}

	var set jwk.Set
	if err == nil {
		set = jwk.NewSet()
		err = set.AddKey(publicKey)
	}

	if err == nil {
		updated.Marshaled.Set, err = json.Marshal(set)
	}

	if err == nil {
		k.current.Store(updated)
	}

	return
}

func (k *Key) Alg() jwa.KeyAlgorithm {
	return k.alg
}

func (k *Key) Current() GeneratedKey {
	return k.current.Load().(GeneratedKey)
}

type KeyHandler struct {
	logger *zap.Logger
	key    *Key
}

func NewKeyHandler(logger *zap.Logger, key *Key) *KeyHandler {
	return &KeyHandler{
		logger: logger,
		key:    key,
	}
}

func (kh *KeyHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	marshaled := kh.key.Current().Marshaled.Public
	response.Header().Set("Content-Type", "application/jwk+json")
	response.Write(marshaled)
}

func ProvideKey() fx.Option {
	return fx.Provide(
		NewKey,
		NewKeyHandler,
	)
}
