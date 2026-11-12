// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import "time"

// nowFunc is the wall clock, the only one in production code, and tests
// replace it. It bounds a --kb bundle's created_at against forgery; evaluation
// time never comes from it.
var nowFunc = time.Now
