// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	ErrNoSuchKey = errors.New("no key exists with that KID")
)

// KeyStore represents storage, possibly external, for keys.
type KeyStore interface {
	// Store inserts the given key into this storage. Care must be taken
	// not to store private keys in unsafe, external locations.
	Store(Key) error

	// Load retrieves the Key with the given kid. If no such key exists,
	// this method returns ErrNoSuckKey.
	Load(kid string) (Key, error)

	// LoadAll loads all keys known to this storage. Note that this method
	// may filter expired keys, depending on the implementation.
	LoadAll() ([]Key, error)

	// Delete removes a key from this storage. If no such key exists,
	// this method returns ErrNoSuchKey.
	Delete(kid string) error
}

// InMemoryKeyStore is a KeyStore that uses a simple map guarded
// by a read/write mutex. Instances must be created with NewInMemoryKeyStore.
type InMemoryKeyStore struct {
	lock sync.RWMutex
	keys map[string]Key
}

func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys: make(map[string]Key),
	}
}

func (s *InMemoryKeyStore) Store(k Key) error {
	s.lock.Lock()
	s.keys[k.KID] = k
	s.lock.Unlock()
	return nil
}

func (s *InMemoryKeyStore) Load(kid string) (k Key, err error) {
	var exists bool
	s.lock.RLock()
	k, exists = s.keys[kid]
	s.lock.RUnlock()

	if !exists {
		err = ErrNoSuchKey
	}

	return
}

func (s *InMemoryKeyStore) LoadAll() (ks []Key, err error) {
	s.lock.RLock()

	ks = make([]Key, 0, len(s.keys))
	for _, k := range s.keys {
		ks = append(ks, k)
	}

	s.lock.RUnlock()
	return
}

func (s *InMemoryKeyStore) Delete(kid string) (err error) {
	s.lock.Lock()

	if _, exists := s.keys[kid]; exists {
		delete(s.keys, kid)
	} else {
		err = ErrNoSuchKey
	}

	s.lock.Unlock()
	return
}

// KeyHandler renders PUBLIC keys over HTTP.
type KeyHandler struct {
	logger      *zap.Logger
	keyAccessor *KeyAccessor
	keyStore    KeyStore
}

func NewKeyHandler(logger *zap.Logger, keyAccessor *KeyAccessor, keyStore KeyStore) *KeyHandler {
	return &KeyHandler{
		logger:      logger,
		keyAccessor: keyAccessor,
		keyStore:    keyStore,
	}
}

func (kh *KeyHandler) writeKey(response http.ResponseWriter, key Key) {
	response.Header().Set("Content-Type", "application/jwk+json")
	key.WriteTo(response)
}

// ServeHTTP serves up the JWK format of generated keys. If this handler receives a path variable
// named "kid", that is used to lookup the key to render. Otherwise, this handler returns the current
// verification key.
func (kh *KeyHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if kid := request.PathValue("kid"); len(kid) > 0 {
		if key, err := kh.keyStore.Load(kid); err == nil {
			kh.writeKey(response, key)
		} else {
			response.WriteHeader(http.StatusNotFound)
		}
	} else if key, err := kh.keyAccessor.Load(); err == nil {
		kh.writeKey(response, key)
	} else {
		response.WriteHeader(http.StatusServiceUnavailable)
	}
}

// KeysHandler serves up the set of all keys in a Keys.
type KeysHandler struct {
	logger   *zap.Logger
	keyStore KeyStore
}

func NewKeysHandler(l *zap.Logger, keyStore KeyStore) *KeysHandler {
	return &KeysHandler{
		logger:   l,
		keyStore: keyStore,
	}
}

func (kh *KeysHandler) fetchKeySet() (set jwk.Set, err error) {
	var keys []Key
	keys, err = kh.keyStore.LoadAll()
	if err == nil {
		set, err = NewPublicSet(keys...)
	}

	return
}

// ServeHTTP serves up the JWK key set in jwk-set format.
func (kh *KeysHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	var data []byte
	set, err := kh.fetchKeySet()
	if err == nil {
		data, err = json.Marshal(set)
	}

	if err == nil {
		response.Header().Set("Content-Type", "application/jwk-set+json")
		response.Write(data)
	} else {
		response.WriteHeader(http.StatusInternalServerError)
	}
}

func ProvideKeyStore() fx.Option {
	return fx.Provide(
		fx.Annotate(
			NewInMemoryKeyStore,
			fx.As(new(KeyStore)),
		),
		NewKeyHandler,
		NewKeysHandler,
	)
}
