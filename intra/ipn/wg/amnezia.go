// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wg

import (
	"fmt"
)

// Amnezia holds the AmneziaWG obfuscation parameters parsed from a
// WireGuard config ([Interface] section). These values are NOT applied
// here: they are forwarded verbatim to the amneziawg-go device via UAPI
// (see wgIfConfigOf in ../wgproxy.go), and the engine itself applies
// them when sending/receiving packets.
//
// Rethink previously re-implemented a subset of this obfuscation in the
// Bind layer (Amnezia.send/recv in this file, hooked from wgconn.go).
// That is deleted: the engine already MACs the standard header, and the
// Bind layer rewriting it afterwards made peers drop handshakes as
// invalid mac1. Do not re-add any Bind-layer packet rewriting.
//
// Field names are the contract with the app (WgInterface in rethink-app):
// jc, jmin, jmax, s1, s2, h1, h2, h3, h4 are parsed by the app today.
// s3, s4, i1-i5 and header_protection_key have no app-side field yet;
// they are accepted here so a config pasted/imported with them works,
// and so the UI workstream can add matching fields later using these
// exact UAPI key names.
//
// UAPI keys (amneziawg-go/device/uapi.go):
//   jc, jmin, jmax           - junk packet count / min / max size
//   s1, s2, s3, s4           - init / response / cookie / transport padding
//   h1, h2, h3, h4           - init / response / cookie / transport header
//                              ranges ("<lo>" or "<lo>-<hi>")
//   i1, i2, i3, i4, i5       - init-packet obfuscation chains
//                              ("<tag ...>..." spec, see device/obf.go)
//   header_protection_key    - 32-byte hex key protecting packet headers
type Amnezia struct {
	id string

	Jc, Jmin, Jmax uint16 // junk packet count, min, max

	S1, S2, S3, S4 uint16 // handshake init/resp/cookie/transport pkt padding
	H1, H2, H3, H4 uint32 // modified msg types [4]byte

	I1, I2, I3, I4, I5 string // init-packet obfuscation chain specs
	HeaderProtectionKey string // 32-byte hex key
}

func NewAmnezia(id string) *Amnezia {
	return &Amnezia{
		id: id,
	}
}

func (a *Amnezia) String() string {
	if a == nil {
		return "<nil>"
	}
	if !a.Set() {
		return "<unset>"
	}
	return fmt.Sprintf("%s: amnezia: jc(%d), jmin(%d), jmax(%d), s1(%d), s2(%d), s3(%d), s4(%d), h1(%d), h2(%d), h3(%d), h4(%d), i1(%q), i2(%q), i3(%q), i4(%q), i5(%q), hpk(%t)",
		a.id, a.Jc, a.Jmin, a.Jmax, a.S1, a.S2, a.S3, a.S4, a.H1, a.H2, a.H3, a.H4,
		a.I1, a.I2, a.I3, a.I4, a.I5, len(a.HeaderProtectionKey) > 0)
}

func (a *Amnezia) Set() bool {
	if a == nil {
		return false
	}

	return a.Jc > 0 || a.Jmin > 0 || a.Jmax > 0 ||
		a.S1 > 0 || a.S2 > 0 || a.S3 > 0 || a.S4 > 0 ||
		a.H1 > 0 || a.H2 > 0 || a.H3 > 0 || a.H4 > 0 ||
		len(a.I1) > 0 || len(a.I2) > 0 || len(a.I3) > 0 ||
		len(a.I4) > 0 || len(a.I5) > 0 ||
		len(a.HeaderProtectionKey) > 0
}

func (a *Amnezia) Same(b *Amnezia) bool {
	if a == nil && b == nil {
		return false
	} else if a == nil || b == nil {
		return false
	}

	return a.Jc == b.Jc &&
		a.Jmin == b.Jmin &&
		a.Jmax == b.Jmax &&
		a.S1 == b.S1 &&
		a.S2 == b.S2 &&
		a.S3 == b.S3 &&
		a.S4 == b.S4 &&
		a.H1 == b.H1 &&
		a.H2 == b.H2 &&
		a.H3 == b.H3 &&
		a.H4 == b.H4 &&
		a.I1 == b.I1 &&
		a.I2 == b.I2 &&
		a.I3 == b.I3 &&
		a.I4 == b.I4 &&
		a.I5 == b.I5 &&
		a.HeaderProtectionKey == b.HeaderProtectionKey
}
