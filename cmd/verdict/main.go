// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/uddeshya-world/verdict/internal/cli"
)

func main() {
	if err := cli.Execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "verdict: %v\n", err)
		var ee *cli.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.Code)
		}
		os.Exit(1)
	}
}
