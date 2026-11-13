// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo holds the version string reported by the CLI.
package buildinfo

// DefaultVersion is what a build without a release ldflag reports.
const DefaultVersion = "dev"

// Version is the release version without its leading "v". The release
// workflow sets it at link time:
//
//	-ldflags "-X github.com/uddeshya-world/verdict/internal/buildinfo.Version=0.2.0"
//
// It is a plain string so the same inputs give the same binary. It is not
// derived from VCS state, so a source build reports "dev" wherever it is
// built, and golden reports produced by tests do not depend on ldflags.
var Version = DefaultVersion

// ModulePath is the canonical module path.
const ModulePath = "github.com/uddeshya-world/verdict"
