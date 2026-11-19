// Command configtabs writes a TOML config example, read from stdin, as json or nix for the docs' format tabs.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/toppk/sitescope/internal/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: configtabs json|nix < example.toml")
		os.Exit(2)
	}
	b, err := io.ReadAll(os.Stdin)
	if err == nil {
		err = config.ConvertTOML(os.Stdout, b, os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configtabs:", err)
		os.Exit(1)
	}
}
