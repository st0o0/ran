// Package crowdsecprofile embeds the example CrowdSec profile that matches the
// alerts rán sends. The same bytes are printed by `ran crowdsec-profile`, included
// in the documentation and mounted by the CrowdSec integration test.
package crowdsecprofile

import _ "embed"

//go:embed profiles.yaml
var profiles string

// YAML returns the embedded profiles.yaml.
func YAML() string { return profiles }
