package config

import (
	"log/slog"
	"sync"

	"github.com/st0o0/ran/internal/fingerprint"
)

// fingerprintState resolves the banner profile once, so every trap of the
// process sees the same values even when the seed could not be persisted.
type fingerprintState struct {
	once    sync.Once
	profile *fingerprint.Profile
}

// Fingerprint returns the banner profile of this instance. In seeded mode the
// first call reads or creates the seed file; later calls return the same
// profile. A Config that was not built by Load (tests) has the fixed profile.
// The logger of the first call reports the seed handling.
func (c *Config) Fingerprint(logger *slog.Logger) *fingerprint.Profile {
	if c.fp == nil {
		return fingerprint.Fixed()
	}
	c.fp.once.Do(func() {
		if c.fp.profile == nil {
			c.fp.profile = fingerprint.Load(c.FingerprintMode, c.FingerprintSeedPath, logger)
		}
	})
	return c.fp.profile
}

// SetFingerprint replaces the banner profile. It is meant for tests and must
// be called before the traps are built.
func (c *Config) SetFingerprint(p *fingerprint.Profile) {
	c.fp = &fingerprintState{profile: p}
}
