# ADR 0001: A single Go CLI for the foundation

## Status

Accepted for v0.1.

## Context

The design notes recommend Go, a Cobra CLI, and a later server and UI in the same binary. This slice has to be something a reviewer can build and run offline, without standing up a service.

## Decision

The foundation is a Go 1.22 module, command `verdict`, using Cobra. The module path is `github.com/uddeshya-world/verdict`. There is no server, no embedded web UI, and no database in this version.

Go fits a single static binary that can be copied into an air-gapped environment. Cobra is limited to argument parsing. Evaluation does not depend on it.

## Consequences

Operators script `verdict drill`. A future server would call the same engine package rather than shell out. Until that exists, the README must not describe a web funnel or an API.

## Alternatives

A Python tool would be shorter to prototype and harder to ship as one file with a predictable runtime. Deferring all code until a UI exists would not test the verdict rules. The engine is the part that can be wrong in a dangerous way, so it comes first.
