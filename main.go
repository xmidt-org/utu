package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"go.uber.org/fx"
)

func run(args []string, options ...kong.Option) {
	app := fx.New(
		ProvideCommandLine(args, options...),
		ProvideLogging(),
		ProvideKey(),
		ProvideSigner(),
		ProvideIssuer(),
		ProvideServer(),
	)

	app.Run()
	if err := app.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}

func main() {
	run(os.Args[1:])
}
