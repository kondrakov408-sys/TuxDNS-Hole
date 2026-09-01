package filter

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ignoredHosts are common local hostnames present in standard hosts files that should not be blocked.
var ignoredHosts = map[string]struct{}{
	"localhost":                  {},
	"localhost.localdomain":      {},
	"local":                      {},
	"broadcasthost":              {},
	"ip6-localhost":              {},
	"ip6-loopback":               {},
	"ip6-localnet":               {},
	"ip6-mcastprefix":            {},
	"ip6-allnodes":               {},
	"ip6-allrouters":             {},
	"ip6-allhosts":               {},
	"0.0.0.0":                    {},
	"255.255.255.255":            {},
}

// ParseHosts parses domain names from an io.Reader containing hosts file format or plain domain lists.
func ParseHosts(r io.Reader) ([]string, error) {
	var domains []string
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(r)
	// Allow scanning lines up to 64KB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Strip inline comments
		if idx := strings.IndexByte(line, '#'); idx != -1 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		// Split line by whitespace
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Check if first field is an IP (hosts format)
		first := fields[0]
		if first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" || first == "::" {
			// Hosts format: IP followed by one or more hostnames
			for _, host := range fields[1:] {
				clean := normalizeDomain(host)
				if isValidDomain(clean) {
					if _, exists := seen[clean]; !exists {
						seen[clean] = struct{}{}
						domains = append(domains, clean)
					}
				}
			}
		} else if len(fields) == 1 {
			// Plain domain list (single domain per line or wildcard)
			clean := normalizeDomain(first)
			if isValidDomain(clean) {
				if _, exists := seen[clean]; !exists {
					seen[clean] = struct{}{}
					domains = append(domains, clean)
				}
			}
		} else {
			// Could be adblock syntax or other IP format; treat non-IP tokens as potential domains if valid
			for _, token := range fields {
				clean := normalizeDomain(token)
				if isValidDomain(clean) {
					if _, exists := seen[clean]; !exists {
						seen[clean] = struct{}{}
						domains = append(domains, clean)
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return domains, fmt.Errorf("error reading hosts input: %w", err)
	}

	return domains, nil
}

// FetchURL downloads a blocklist from a remote HTTP/HTTPS URL and parses its domains.
func FetchURL(ctx context.Context, rawURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}

	req.Header.Set("User-Agent", "TuxDNS-Hole/1.0 (+https://github.com/tuxdns/tuxdnshole)")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-200 status %d for %q", resp.StatusCode, rawURL)
	}

	return ParseHosts(resp.Body)
}

// LoadFile reads a local hosts or domain list file and parses its domains.
func LoadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %q: %w", path, err)
	}
	defer f.Close()

	return ParseHosts(f)
}

// normalizeDomain sanitizes a domain string to lowercase and trims surrounding punctuation/dots.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	// Remove leading || (AdGuard syntax) or *. (wildcard)
	d = strings.TrimPrefix(d, "||")
	d = strings.TrimPrefix(d, "^")
	d = strings.TrimSuffix(d, "^")
	d = strings.TrimSuffix(d, ".")
	return d
}

// isValidDomain checks if a domain string is valid for filtering.
func isValidDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	if _, ignored := ignoredHosts[d]; ignored {
		return false
	}
	// Check for wildcard prefix
	clean := strings.TrimPrefix(d, "*.")
	clean = strings.TrimPrefix(clean, ".")
	if clean == "" {
		return false
	}
	// Must contain no whitespace or invalid characters
	if strings.ContainsAny(clean, " /\\:;*?\"<>|&$#@!%^()[]{}`~") {
		return false
	}
	return true
}
