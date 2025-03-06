// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Network  string            `default:"tcp" enum:"tcp,tcp4,tcp6" help:"the network for the server to bind on"`
	Address  string            `default:":8080" help:"the bind address for the server"`
	Issuer   string            `short:"i" default:"utu" help:"the issuer for issued JWTs (iss)"`
	Subject  string            `short:"s" default:"utu" help:"the subject for issued JWTs (sub)"`
	Expires  time.Duration     `short:"e" default:"24h" help:"how long until issued JWTs expire.  used to compute the exp claim."`
	Audience []string          `short:"a" optional:"" help:"the audience (aud) for issued JWTs"`
	Claims   map[string]string `optional:"" help:"the set of arbitrary claims for issued JWTs"`

	KeyType  string `enum:"EC,RSA" default:"EC" help:"the key type (kty) used to sign and verify JWTs"`
	KeySize  int    `default:"2048" help:"the bit length for keys. used only for RSA keys."`
	KeyCurve string `default:"P-256" enum:"P-256,P-384,P-521" help:"the elliptic curve for key generation. used only for EC keys."`
}

func NewCLI(args []string, options ...kong.Option) (cli CLI, kctx *kong.Context, err error) {
	options = append(
		[]kong.Option{
			kong.Description("labweek JWT issuer with lua integration"),
			kong.UsageOnError(),
		},
		options...,
	)

	var k *kong.Kong
	k, err = kong.New(&cli, options...)
	if err == nil {
		kctx, err = k.Parse(args)
	}

	return
}
