// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

import (
	"net"
)

// AetherOptions carries the configuration for the Aether engine proxy
// (see intra/ipn/aether.go): the vendored Aether core (native/aether in
// rethink-app) serves a local SOCKS5 proxy that firestack dials through,
// exactly like Orbot's SOCKS5 listener, except the engine runs in-process
// in the app instead of in another app.
//
// The engine is local-only by design: only loopback listen addresses are
// accepted. The Tor-exit listener (when Tor rides inside the tunnel) is
// a second SOCKS5 on 1820.
const (
	// DefaultSocksAddr is the engine's main SOCKS5 listener.
	AetherDefaultSocksAddr = "127.0.0.1:1819"
	// DefaultTorSocksAddr is the engine's Tor-exit SOCKS5 listener,
	// present only when Tor runs inside the tunnel (--tor).
	AetherDefaultTorSocksAddr = "127.0.0.1:1820"
)

// AetherOptions define the Aether engine proxy options.
type AetherOptions struct {
	// ID is the proxy id the app registers the engine under ("AETHER").
	ID string
	// SocksAddr is the engine's SOCKS5 listen address (loopback only).
	SocksAddr string
	// TorSocksAddr is the engine's Tor-exit SOCKS5 listen address
	// (loopback only); empty when Tor is not in use.
	TorSocksAddr string
	// Enabled reports whether the engine is expected to be running.
	Enabled bool
}

// DefaultAetherOptions returns the standard Aether engine options.
func DefaultAetherOptions() *AetherOptions {
	return &AetherOptions{
		ID:           "AETHER",
		SocksAddr:    AetherDefaultSocksAddr,
		TorSocksAddr: AetherDefaultTorSocksAddr,
		Enabled:      false,
	}
}

// ProxyOptions converts these options into the scheme-based options the
// proxifier understands ("aether" scheme; see proxifier.fromOpts).
// Returns nil when the listen address does not parse.
func (o *AetherOptions) ProxyOptions() *ProxyOptions {
	if o == nil || len(o.SocksAddr) <= 0 {
		return nil
	}
	ip, port, err := net.SplitHostPort(o.SocksAddr)
	if err != nil {
		return nil
	}
	return NewAuthProxyOptions("aether", "" /*user*/, "" /*password*/, ip, port, nil)
}
