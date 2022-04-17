<div align="center">
<h1>q</h1>

A tiny command line DNS client with support for UDP, TCP, DoT, DoH, DoQ, and ODoH.

[![Release](https://img.shields.io/github/v/release/natesales/q?style=for-the-badge)](https://github.com/natesales/q/releases)
![Coverage](coverage_badge.png)
[![Go Report](https://goreportcard.com/badge/github.com/natesales/q?style=for-the-badge)](https://goreportcard.com/report/github.com/natesales/q)
[![License](https://img.shields.io/github/license/natesales/q?style=for-the-badge)](https://raw.githubusercontent.com/natesales/q/main/LICENSE)

![q screenshot](carbon.svg)
</div>

### Usage
```
Usage:
  q [OPTIONS] [@server] [type...] [name]

All long form (--) flags can be toggled with the dig-standard +[no]flag notation.

Application Options:
  -q, --qname=            Query name
  -s, --server=           DNS server
  -t, --type=             RR type
  -x, --reverse           Reverse lookup
  -d, --dnssec            Set the DO (DNSSEC OK) bit in the OPT record
  -n, --nsid              Set EDNS0 NSID opt
      --subnet=           Set EDNS0 client subnet
  -f, --format=           Output format (pretty, json, raw) (default: pretty)
  -c, --chaos             Use CHAOS query class
  -p, --odoh-proxy=       ODoH proxy
      --timeout=          Query timeout duration (default: 10s)
      --aa                Set AA (Authoritative Answer) flag in query
      --ad                Set AD (Authentic Data) flag in query
      --cd                Set CD (Checking Disabled) flag in query
      --rd                Set RD (Recursion Desired) flag in query
      --ra                Set RA (Recursion Available) flag in query
      --z                 Set Z (Zero) flag in query
  -i, --tls-no-verify     Disable TLS certificate verification
      --tls-min-version=  Minimum TLS version to use (default: 1.0)
      --tls-max-version=  Maximum TLS version to use (default: 1.3)
      --http-user-agent=  HTTP user agent
      --http-method=      HTTP method (default: GET)
      --quic-alpn-tokens= QUIC ALPN tokens (default: doq, doq-i11)
      --udp-buffer=       Set EDNS0 UDP size in query (default: 4096)
  -v, --verbose           Show verbose log messages
  -V, --version           Show version and exit

Help Options:
  -h, --help              Show this help message
```

### Demo

[![asciicast](https://asciinema.org/a/XdWPPvZgx4hEBFwGnGwL13bsZ.svg)](https://asciinema.org/a/XdWPPvZgx4hEBFwGnGwL13bsZ)

### Protocol Support
- UDP/TCP DNS ([RFC 1034](https://tools.ietf.org/html/rfc1034))
- DNS over TLS ([RFC 7858](https://tools.ietf.org/html/rfc7858))
- DNS over HTTPS ([RFC 8484](https://tools.ietf.org/html/rfc8484))
- DNS over QUIC ([draft-ietf-dprive-dnsoquic-11](https://tools.ietf.org/html/draft-ietf-dprive-dnsoquic-11))
- Oblivious DNS over HTTPS ([draft-pauly-dprive-oblivious-doh-06](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh-11))

### Installation
`q` is available as a deb/rpm for apt/yum in my [public code repositories](https://github.com/natesales/repo), as a binary under [releases](https://github.com/natesales/q/releases), and in the AUR as [q-dns-git](https://aur.archlinux.org/packages/q-dns-git/).
