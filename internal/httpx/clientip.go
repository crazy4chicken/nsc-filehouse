package httpx

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPKey struct{}

// ClientIPSlot records the resolved client IP so that middleware wrapping the
// request (access logging) can read it after the inner chain completed.
type ClientIPSlot struct {
	IP string
}

type clientIPSlotKey struct{}

// NewClientIPSlot stores a fresh slot in ctx and returns it.
func NewClientIPSlot(ctx context.Context) (context.Context, *ClientIPSlot) {
	slot := &ClientIPSlot{}
	return context.WithValue(ctx, clientIPSlotKey{}, slot), slot
}

// EnsureClientIPSlot reuses the slot already present in ctx, or installs a new
// one. Middleware that run in different orders share the resolved IP through
// this helper.
func EnsureClientIPSlot(ctx context.Context) (context.Context, *ClientIPSlot) {
	if slot := ClientIPSlotFromContext(ctx); slot != nil {
		return ctx, slot
	}
	return NewClientIPSlot(ctx)
}

// ClientIPSlotFromContext returns the slot installed by NewClientIPSlot, if any.
func ClientIPSlotFromContext(ctx context.Context) *ClientIPSlot {
	slot, _ := ctx.Value(clientIPSlotKey{}).(*ClientIPSlot)
	return slot
}

// WithClientIP returns a context carrying the resolved client IP.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIPFromContext returns the client IP resolved by the ClientIP middleware.
func ClientIPFromContext(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip, _ := r.Context().Value(clientIPKey{}).(string)
	return ip
}

// ClientIP resolves the client IP of a request.
//
// X-Forwarded-For is honoured only when the direct peer is a loopback address or
// matches one of the trusted prefixes; the header is then walked right to left
// and the first untrusted address wins (same rule as teamusers).
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	if r == nil {
		return ""
	}
	peer, peerOK := parseRemoteAddr(r.RemoteAddr)
	if !peerOK {
		return ""
	}
	if !IsTrusted(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hops = append(hops, part)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if IsTrusted(addr, trusted) {
			continue
		}
		return addr.String()
	}
	// Every hop is trusted or unparsable: fall back to the origin of the chain.
	for _, hop := range hops {
		if addr, err := netip.ParseAddr(hop); err == nil {
			return addr.Unmap().String()
		}
	}
	return peer.String()
}

// IsTrusted reports whether addr is loopback or covered by one of the prefixes.
func IsTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true
	}
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parseRemoteAddr(remoteAddr string) (netip.Addr, bool) {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = strings.Trim(remoteAddr, "[]")
	}
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
