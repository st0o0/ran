package crowdsecprofile

import "strings"

// TestedImage is the CrowdSec image (tag and digest) the integration test runs
// the shipped profile against. Renovate keeps it current (see renovate.json), so
// a CrowdSec upgrade that breaks the profile fails CI instead of production. The
// documentation derives its "tested version" from it.
//
// renovate: datasource=docker depName=crowdsecurity/crowdsec
const TestedImage = "crowdsecurity/crowdsec:v1.8.2@sha256:65b74942f7e7ed5c60fde4ac15fc4ba715904c398c8b16dd451f4907d90347d4"

// TestedVersion returns the tag of TestedImage, for example "v1.8.1".
func TestedVersion() string {
	ref, _, _ := strings.Cut(TestedImage, "@")
	_, tag, _ := strings.Cut(ref, ":")
	return tag
}
