package dns

import (
	"crypto/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var cgnatSubnet = &net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

// ApplyEDNS0Padding pads a DNS message to a multiple of blockSize bytes (RFC 7830 / RFC 8467).
func ApplyEDNS0Padding(req *dns.Msg, blockSize int) {
	if blockSize <= 0 {
		blockSize = 128
	}

	opt := req.IsEdns0()
	if opt == nil {
		req.SetEdns0(1232, false)
		opt = req.IsEdns0()
	}

	// Remove existing EDNS0_PADDING options
	cleanOptions := make([]dns.EDNS0, 0, len(opt.Option))
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0PADDING {
			cleanOptions = append(cleanOptions, o)
		}
	}

	// Insert an empty padding option to accurately calculate base wire overhead (OptionCode 2B + OptionLength 2B)
	padOption := &dns.EDNS0_PADDING{Padding: []byte{}}
	opt.Option = append(cleanOptions, padOption)

	// Measure current length with empty padding option
	currentLen := req.Len()
	rem := currentLen % blockSize
	if rem != 0 {
		padLen := blockSize - rem
		padOption.Padding = make([]byte, padLen)
	}
}

// Randomize0x20 randomly flips the case of ASCII alphabetic characters in a domain name (bit 0x20).
func Randomize0x20(name string) string {
	if name == "" {
		return name
	}

	b := []byte(name)
	// Use crypto/rand to generate random byte stream
	randBytes := make([]byte, (len(b)+7)/8)
	_, _ = rand.Read(randBytes)

	for i := range b {
		c := b[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			byteIdx := i / 8
			bitIdx := uint(i % 8)
			isUpper := (randBytes[byteIdx] & (1 << bitIdx)) != 0
			if isUpper {
				b[i] = c &^ 0x20 // uppercase
			} else {
				b[i] = c | 0x20 // lowercase
			}
		}
	}

	return string(b)
}

// Is0x20Match checks if the returned domain name preserves the exact casing of the query name.
func Is0x20Match(sentQueryName, receivedAnswerName string) bool {
	return sentQueryName == receivedAnswerName
}

// IsPrivateOrLocalIP checks if an IP address belongs to RFC 1918, loopback, link-local, or CGNAT ranges.
func IsPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	// Check 100.64.0.0/10 Carrier-Grade NAT (RFC 6598)
	if ip4 := ip.To4(); ip4 != nil {
		if cgnatSubnet.Contains(ip4) {
			return true
		}
	}

	return false
}

// IsAllowedLocalDomain checks if a domain matches local domain whitelist patterns (e.g. *.local, *.lan, router.lan).
func IsAllowedLocalDomain(domain string, patterns []string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, p := range patterns {
		pat := strings.ToLower(strings.TrimSuffix(p, "."))
		if strings.HasPrefix(pat, "*.") {
			suffix := strings.TrimPrefix(pat, "*.")
			if d == suffix || strings.HasSuffix(d, "."+suffix) {
				return true
			}
		} else if pat == d {
			return true
		}
	}
	return false
}

// FilterDNSRebinding inspects answer records and returns true if dangerous private IPs were found.
func FilterDNSRebinding(resp *dns.Msg, domain string, allowedPatterns []string) (hasRebinding bool) {
	if resp == nil || len(resp.Answer) == 0 {
		return false
	}

	if IsAllowedLocalDomain(domain, allowedPatterns) {
		return false
	}

	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if IsPrivateOrLocalIP(r.A) {
				return true
			}
		case *dns.AAAA:
			if IsPrivateOrLocalIP(r.AAAA) {
				return true
			}
		}
	}

	return false
}

// QueryLogEntry represents a zero-disk in-memory query record.
type QueryLogEntry struct {
	Timestamp time.Time
	Domain    string
	Qtype     uint16
	Status    string
	RTT       time.Duration
}

// RingBuffer provides a high-throughput, lock-free circular query log buffer in RAM.
type RingBuffer struct {
	buffer []*atomic.Pointer[QueryLogEntry]
	size   uint64
	cursor atomic.Uint64
}

// NewRingBuffer creates a lock-free in-memory query ring buffer.
func NewRingBuffer(size int) *RingBuffer {
	if size <= 0 {
		size = 1000
	}
	rb := &RingBuffer{
		buffer: make([]*atomic.Pointer[QueryLogEntry], size),
		size:   uint64(size),
	}
	for i := range rb.buffer {
		rb.buffer[i] = &atomic.Pointer[QueryLogEntry]{}
	}
	return rb
}

// Push records a query log entry without mutex contention.
func (rb *RingBuffer) Push(entry *QueryLogEntry) {
	if rb == nil || rb.size == 0 || entry == nil {
		return
	}
	idx := rb.cursor.Add(1) % rb.size
	rb.buffer[idx].Store(entry)
}

// GetRecent returns the most recent N entries from RAM.
func (rb *RingBuffer) GetRecent(limit int) []*QueryLogEntry {
	if rb == nil || rb.size == 0 || limit <= 0 {
		return nil
	}

	if uint64(limit) > rb.size {
		limit = int(rb.size)
	}

	currentCursor := rb.cursor.Load()
	entries := make([]*QueryLogEntry, 0, limit)

	for i := 0; i < limit; i++ {
		// Traverse backward from current cursor
		idx := (currentCursor + rb.size - uint64(i)) % rb.size
		ptr := rb.buffer[idx].Load()
		if ptr != nil {
			entries = append(entries, ptr)
		}
	}

	return entries
}

// Len returns the capacity size of the ring buffer.
func (rb *RingBuffer) Len() int {
	if rb == nil {
		return 0
	}
	return int(rb.size)
}
