// Package recon answers "who owns this address, and where is it?" entirely
// offline.
//
// Privacy is the design driver: looking each address up against a live WHOIS or
// geo-IP API would send every destination the user contacts to a third party —
// exactly the leak this product exists to surface. Instead a public dataset is
// pulled DOWN once (ip2asn from iptoasn.com: address range -> AS number, AS
// owner, country) and every lookup is a local binary search.
//
// Cost, measured against the real dataset: ~45 MB cached on disk, ~21 MB
// resident once loaded, ~0.5 s to parse at startup, and O(log n) per lookup.
// That is the price of not telling a third party where the user goes; the
// --no-recon flag opts out entirely for anyone who would rather not pay it.
package recon

import (
	"bufio"
	"encoding/binary"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Info is what we can say about an address without asking anyone.
type Info struct {
	ASN     uint32 `json:"asn"`
	Org     string `json:"org"`     // AS owner, e.g. "CLOUDFLARENET"
	Country string `json:"country"` // ISO-3166 alpha-2, e.g. "US"
}

func (i Info) Known() bool { return i.ASN != 0 || i.Org != "" || i.Country != "" }

// rangeV4/rangeV6 are sorted, non-overlapping allocations. Org and country
// strings are interned: the dataset has ~500k rows but only a few tens of
// thousands of distinct owners, so sharing them keeps the table compact.
type rangeV4 struct {
	lo, hi uint32
	asn    uint32
	orgIdx int32
	ccIdx  int32
}

type rangeV6 struct {
	lo, hi [16]byte
	asn    uint32
	orgIdx int32
	ccIdx  int32
}

// DB is a loaded ip2asn table.
type DB struct {
	mu   sync.RWMutex
	v4   []rangeV4
	v6   []rangeV6
	strs []string
}

// New returns an empty DB. Lookups return zero Info until Load succeeds, so the
// agent runs fine with no dataset present.
func New() *DB { return &DB{} }

// Loaded reports whether any ranges are available.
func (d *DB) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.v4)+len(d.v6) > 0
}

// Load parses the ip2asn TSV format:
//
//	range_start \t range_end \t AS_number \t country_code \t AS_description
//
// Rows with AS number 0 ("not routed") are skipped.
func (d *DB) Load(r io.Reader) error {
	var (
		v4     []rangeV4
		v6     []rangeV6
		strs   []string
		intern = map[string]int32{}
	)
	idx := func(s string) int32 {
		if s == "" {
			return -1
		}
		if i, ok := intern[s]; ok {
			return i
		}
		i := int32(len(strs))
		strs = append(strs, s)
		intern[s] = i
		return i
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		asn64, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil || asn64 == 0 {
			continue
		}
		lo, err1 := netip.ParseAddr(f[0])
		hi, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		cc := strings.ToUpper(strings.TrimSpace(f[3]))
		if cc == "NONE" {
			cc = ""
		}
		org := strings.TrimSpace(f[4])
		if org == "Not routed" {
			continue
		}

		switch {
		case lo.Is4() && hi.Is4():
			v4 = append(v4, rangeV4{
				lo: b2u32(lo.As4()), hi: b2u32(hi.As4()),
				asn: uint32(asn64), orgIdx: idx(org), ccIdx: idx(cc),
			})
		case lo.Is6() && hi.Is6():
			v6 = append(v6, rangeV6{
				lo: lo.As16(), hi: hi.As16(),
				asn: uint32(asn64), orgIdx: idx(org), ccIdx: idx(cc),
			})
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}

	sort.Slice(v4, func(i, j int) bool { return v4[i].lo < v4[j].lo })
	sort.Slice(v6, func(i, j int) bool { return cmp16(v6[i].lo, v6[j].lo) < 0 })

	d.mu.Lock()
	d.v4, d.v6, d.strs = v4, v6, strs
	d.mu.Unlock()
	return nil
}

// Lookup returns what is known about an address. Unknown addresses yield a zero
// Info rather than an error — absence of data is normal, not a failure.
func (d *DB) Lookup(ipStr string) Info {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return Info{}
	}
	addr = addr.Unmap()

	d.mu.RLock()
	defer d.mu.RUnlock()

	if addr.Is4() {
		key := b2u32(addr.As4())
		i := sort.Search(len(d.v4), func(i int) bool { return d.v4[i].hi >= key })
		if i < len(d.v4) && d.v4[i].lo <= key {
			return d.info(d.v4[i].asn, d.v4[i].orgIdx, d.v4[i].ccIdx)
		}
		return Info{}
	}

	key := addr.As16()
	i := sort.Search(len(d.v6), func(i int) bool { return cmp16(d.v6[i].hi, key) >= 0 })
	if i < len(d.v6) && cmp16(d.v6[i].lo, key) <= 0 {
		return d.info(d.v6[i].asn, d.v6[i].orgIdx, d.v6[i].ccIdx)
	}
	return Info{}
}

func (d *DB) info(asn uint32, orgIdx, ccIdx int32) Info {
	out := Info{ASN: asn}
	if orgIdx >= 0 && int(orgIdx) < len(d.strs) {
		out.Org = d.strs[orgIdx]
	}
	if ccIdx >= 0 && int(ccIdx) < len(d.strs) {
		out.Country = d.strs[ccIdx]
	}
	return out
}

func b2u32(b [4]byte) uint32 { return binary.BigEndian.Uint32(b[:]) }

func cmp16(a, b [16]byte) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}
