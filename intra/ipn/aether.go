// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

// Aether engine as a proxy.
//
// The Aether core (vendored Rust engine in rethink-app's native/aether,
// AGPL-3.0, CluvexStudio) runs in-process in the app and serves a local
// SOCKS5 proxy on 127.0.0.1:1819 (plus 127.0.0.1:1820 for the Tor exit
// when Tor rides inside the tunnel). Firestack routes traffic through it
// exactly like any other SOCKS5 proxy — this type only exists so the
// backend can tell an Aether proxy apart from a user-configured SOCKS5
// proxy (Type() == "aether", id "AETHER") and so the engine's liveness
// can be probed without sending traffic through it.
//
// The engine's lifecycle is owned by the app (AetherEngine /
// AetherController in rethink-app): firestack never starts or stops it,
// it only dials the listener. When the listener is dead, dials fail and
// traffic fails closed — the proxy itself is the kill-switch.
//
// Registration: the app calls Proxifier.AddProxy("AETHER",
// "aether://127.0.0.1:1819"), which reaches here via
// proxifier.fromOpts's "aether" case. The primary traffic path does not
// depend on this id — the TUN egress uses the plain SOCKS5 slot (id
// "S5") that the app points at the same listener — but per-app proxy
// rules can address "AETHER" directly.
type aether struct {
	*socks5
}

var errAetherNotLoopback = errors.New("proxy: aether: engine address must be loopback")

// NewAetherProxy builds an Aether proxy dialing the engine's local SOCKS5
// listener. Only loopback addresses are accepted: the engine never
// listens anywhere else, and a remote "aether" URL is a misconfiguration
// (or an attempt to route traffic to someone else's listener).
func NewAetherProxy(
	id string,
	ctx context.Context,
	ctl protect.Controller,
	px ProxyProvider,
	po *settings.ProxyOptions,
) (*aether, error) {
	if po == nil {
		return nil, errMissingProxyOpt
	}
	// The proxifier builds ProxyOptions from a URL ("aether://127.0.0.1:1819"):
	// depending on the parse path, the host may sit in IP, Host, or IPPort,
	// so check all three before refusing.
	host := po.IP
	if len(host) <= 0 {
		host = po.Host
	}
	if len(host) <= 0 {
		host, _, _ = net.SplitHostPort(po.IPPort)
	}
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if !loopback {
		log.E("proxy: aether: refusing non-loopback engine address %s", po.IPPort)
		return nil, errAetherNotLoopback
	}
	s5, err := NewSocks5Proxy(id, ctx, ctl, px, po)
	if err != nil {
		return nil, err
	}
	log.I("proxy: aether: created %s (engine at %s)", s5.ID(), s5.GetAddr())
	return &aether{socks5: s5}, nil
}

// Type implements x.Proxy: "aether" (distinct from plain "socks5").
func (h *aether) Type() string {
	return AETHER
}

// EngineAddr returns the engine's SOCKS5 listen address (ip:port).
func (h *aether) EngineAddr() string {
	return h.GetAddr()
}

// EngineAlive probes the engine's listener with a bare TCP connect
// (no SOCKS handshake, no traffic). A dead engine means the tunnel
// cannot carry anything — callers use this to surface "engine down"
// instead of letting dials time out one by one.
func (h *aether) EngineAlive() bool {
	addr := h.GetAddr()
	if len(addr) <= 0 {
		return false
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
