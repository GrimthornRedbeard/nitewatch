package resolve

import (
	"net"
	"sync"
)

// LocalNets recognizes addresses that belong to the machine's own networks.
//
// This matters most for IPv6: there is no RFC1918 equivalent, so devices on a
// home LAN hold globally-routable addresses from the ISP-delegated prefix
// (e.g. 2600:1700:13b0:2fc0::/64). Those addresses pass every "is it public?"
// test yet are not the internet — they are the printer, the NAS, the phone.
// Treating them as external buries real outbound traffic in LAN chatter.
type LocalNets struct {
	mu   sync.RWMutex
	nets []*net.IPNet
}

// DetectLocalNets enumerates the host's interface addresses and derives the
// networks it is directly attached to.
func DetectLocalNets() *LocalNets {
	l := &LocalNets{}
	l.Refresh()
	return l
}

// Refresh re-reads interface addresses (networks change when roaming).
func (l *LocalNets) Refresh() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	var nets []*net.IPNet
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		if ipnet.IP.IsLoopback() {
			continue
		}
		// Use the interface's own mask. For a typical IPv6 SLAAC address this
		// is the /64 the whole LAN shares; for IPv4 it's the local subnet.
		nets = append(nets, &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask})
	}
	l.mu.Lock()
	l.nets = nets
	l.mu.Unlock()
}

// IsLocal reports whether ip sits on one of this machine's own networks.
func (l *LocalNets) IsLocal(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsExternal reports whether an address represents genuine off-network traffic:
// routable on the internet AND not on one of our own attached networks.
func (l *LocalNets) IsExternal(ipStr string) bool {
	return IsPublic(ipStr) && !l.IsLocal(ipStr)
}

// Add registers a network as local. Used by tests to pin a known LAN, and
// available for future user-configured "my network" entries (e.g. a VPN range).
func (l *LocalNets) Add(n *net.IPNet) {
	if n == nil {
		return
	}
	l.mu.Lock()
	l.nets = append(l.nets, n)
	l.mu.Unlock()
}
