package config

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// MaxBannerServices bounds RAN_BANNER_SERVICES.
	MaxBannerServices = 10
	// MaxBannerBytes bounds one banner after its escapes are interpreted.
	MaxBannerBytes = 256
	// MaxBannerNameLen bounds the service name.
	MaxBannerNameLen = 32
	// maxEntryInError cuts an entry quoted in an error message.
	maxEntryInError = 64
)

// BannerService is one entry of RAN_BANNER_SERVICES: a TCP port, a short name
// that only appears in logs and alert meta, and the bytes sent on connect.
type BannerService struct {
	Port   int
	Name   string
	Banner []byte
}

// ParseBannerServices parses a comma-separated list of port=name:banner entries
// (at most MaxBannerServices). The banner may contain the escapes \r, \n, \t, \
// and \, (a literal comma); any other escape is an error. The name is limited to
// [a-z0-9_-] and MaxBannerNameLen bytes, ports must be unique and the decoded
// banner must be 1 to MaxBannerBytes bytes. name is the environment variable,
// used in the error messages, which quote the offending entry.
func ParseBannerServices(name, raw string) ([]BannerService, error) {
	var out []BannerService
	seen := map[int]bool{}
	for _, entry := range splitBannerEntries(raw) {
		entry = strings.TrimLeft(entry, " \t")
		if strings.TrimSpace(entry) == "" {
			continue
		}
		if len(out) >= MaxBannerServices {
			return nil, fmt.Errorf("%s has more than %d entries (first extra entry %s); remove some", name, MaxBannerServices, quoteEntry(entry))
		}
		svc, err := parseBannerEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("%s has an invalid entry %s: %v; use port=name:banner, for example 9999=custom:hello\\r\\n", name, quoteEntry(entry), err)
		}
		if seen[svc.Port] {
			return nil, fmt.Errorf("%s has an invalid entry %s: port %d is used twice; ports must be unique", name, quoteEntry(entry), svc.Port)
		}
		seen[svc.Port] = true
		out = append(out, svc)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s must contain at least one port=name:banner entry such as 9999=custom:hello\\r\\n", name)
	}
	return out, nil
}

// splitBannerEntries splits on commas that are not escaped with a backslash. A
// trailing lone backslash stays in the last entry, where the entry parser
// rejects it.
func splitBannerEntries(raw string) []string {
	var out []string
	start := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case ',':
			out = append(out, raw[start:i])
			start = i + 1
		}
	}
	return append(out, raw[start:])
}

func quoteEntry(entry string) string {
	if len(entry) > maxEntryInError {
		entry = entry[:maxEntryInError] + "..."
	}
	return strconv.QuoteToASCII(entry)
}

func parseBannerEntry(entry string) (BannerService, error) {
	portStr, rest, ok := strings.Cut(entry, "=")
	if !ok {
		return BannerService{}, fmt.Errorf("missing port (no '=')")
	}
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return BannerService{}, fmt.Errorf("missing port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || strings.ContainsAny(portStr, "+-") {
		return BannerService{}, fmt.Errorf("invalid port %s; use a port between 1 and 65535", quoteEntry(portStr))
	}
	svcName, bannerRaw, ok := strings.Cut(rest, ":")
	if !ok {
		return BannerService{}, fmt.Errorf("missing ':' between name and banner")
	}
	svcName = strings.TrimSpace(svcName)
	if err := validBannerName(svcName); err != nil {
		return BannerService{}, err
	}
	banner, err := decodeBanner(bannerRaw)
	if err != nil {
		return BannerService{}, err
	}
	if len(banner) == 0 {
		return BannerService{}, fmt.Errorf("the banner is empty")
	}
	if len(banner) > MaxBannerBytes {
		return BannerService{}, fmt.Errorf("the banner is %d bytes, the limit is %d", len(banner), MaxBannerBytes)
	}
	return BannerService{Port: port, Name: svcName, Banner: banner}, nil
}

func validBannerName(s string) error {
	if s == "" {
		return fmt.Errorf("missing service name")
	}
	if len(s) > MaxBannerNameLen {
		return fmt.Errorf("the service name is longer than %d bytes", MaxBannerNameLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return fmt.Errorf("the service name may only contain a-z, 0-9, '_' and '-'")
		}
	}
	return nil
}

// decodeBanner interprets \r, \n, \t, \ and \, and rejects every other escape.
func decodeBanner(s string) ([]byte, error) {
	out := make([]byte, 0, min(len(s), MaxBannerBytes+1))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			return nil, fmt.Errorf("the banner ends with a lone backslash")
		}
		switch s[i] {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		case ',':
			out = append(out, ',')
		default:
			return nil, fmt.Errorf("unknown escape %s; supported escapes are \\r \\n \\t \\\\ and \\,", strconv.QuoteToASCII("\\"+string(rune(s[i]))))
		}
	}
	return out, nil
}
