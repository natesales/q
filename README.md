<div align="center">
<h1>q</h1>

A tiny and feature-rich command line DNS client with support for UDP, TCP, DoT, DoH, DoQ, and ODoH.

[![Release](https://img.shields.io/github/v/release/natesales/q?style=for-the-badge)](https://github.com/natesales/q/releases)
![Coverage](coverage_badge.png)
[![Go Report](https://goreportcard.com/badge/github.com/natesales/q?style=for-the-badge)](https://goreportcard.com/report/github.com/natesales/q)
[![License](https://img.shields.io/github/license/natesales/q?style=for-the-badge)](https://raw.githubusercontent.com/natesales/q/main/LICENSE)

![q screenshot](carbon.svg)
</div>

### Examples

```
q example.com                            Lookup default records for a domain
q example.com MX SOA                     ...or specify a list of types

q example.com MX @9.9.9.9                Query a specific server
q example.com MX @https://dns.quad9.net  ...over HTTPS (or TCP, TLS, QUIC, or ODoH)...
q @sdns://AgcAAAAAAAAAAAAHOS45LjkuOQA    ...or from a DNS Stamp

q example.com MX --format=raw            Output in raw (dig) format
q example.com MX --format=json           ...or as JSON (or YAML)
```

### Usage
```
Usage:
  q [OPTIONS] [@server] [type...] [name]

All long form (--) flags can be toggled with the dig-standard +[no]flag notation.

Application Options:
  -q, --qname=                 Query name
  -s, --server=                DNS server
  -t, --type=                  RR type (e.g. A, AAAA, MX, etc.) or type integer
  -x, --reverse                Reverse lookup
  -d, --dnssec                 Set the DO (DNSSEC OK) bit in the OPT record
  -n, --nsid                   Set EDNS0 NSID opt
      --subnet=                Set EDNS0 client subnet
  -c, --chaos                  Use CHAOS query class
  -C=                          Set query class (default: IN 0x01) (default: 1)
  -p, --odoh-proxy=            ODoH proxy
      --timeout=               Query timeout (default: 10s)
      --pad                    Set EDNS0 padding
      --http3                  Use HTTP/3 for DoH
      --no-id-check            Disable checking of DNS response ID
      --no-reuse-conn          Use a new connection for each query
      --recaxfr                Perform recursive AXFR
  -f, --format=                Output format (pretty, json, yaml, raw) (default: pretty)
      --pretty-ttls            Format TTLs in human readable format (default: true)
      --color                  Enable color output
      --question               Show question section
      --answer                 Show answer section (default: true)
      --authority              Show authority section
      --additional             Show additional section
  -S, --stats                  Show time statistics
      --all                    Show all sections and statistics
  -w                           Resolve ASN/ASName for A and AAAA records
  -r, --value                  Show record values only
      --aa                     Set AA (Authoritative Answer) flag in query
      --ad                     Set AD (Authentic Data) flag in query
      --cd                     Set CD (Checking Disabled) flag in query
      --rd                     Set RD (Recursion Desired) flag in query (default: true)
      --ra                     Set RA (Recursion Available) flag in query
      --z                      Set Z (Zero) flag in query
      --t                      Set TC (Truncated) flag in query
  -i, --tls-no-verify          Disable TLS certificate verification
      --tls-server-name=       TLS server name for host verification
      --tls-min-version=       Minimum TLS version to use (default: 1.0)
      --tls-max-version=       Maximum TLS version to use (default: 1.3)
      --tls-next-protos=       TLS next protocols for ALPN
      --tls-cipher-suites=     TLS cipher suites
      --http-user-agent=       HTTP user agent
      --http-method=           HTTP method (default: GET)
      --quic-alpn-tokens=      QUIC ALPN tokens (default: doq, doq-i11)
      --quic-no-pmtud          Disable QUIC PMTU discovery
      --quic-no-length-prefix  Don't add RFC 9250 compliant length prefix
      --default-rr-types=      Default record types (default: A, AAAA, NS, MX, TXT, CNAME)
      --udp-buffer=            Set EDNS0 UDP size in query (default: 1232)
  -v, --verbose                Show verbose log messages
      --trace                  Show trace log messages
  -V, --version                Show version and exit

Help Options:
  -h, --help                   Show this help message
```

### Demo

[![asciicast](https://asciinema.org/a/XdWPPvZgx4hEBFwGnGwL13bsZ.svg)](https://asciinema.org/a/XdWPPvZgx4hEBFwGnGwL13bsZ)

### Protocol Support

- UDP/TCP DNS ([RFC 1034](https://tools.ietf.org/html/rfc1034))
- DNS over TLS ([RFC 7858](https://tools.ietf.org/html/rfc7858))
- DNS over HTTPS ([RFC 8484](https://tools.ietf.org/html/rfc8484))
- DNS over QUIC ([RFC 9250](https://tools.ietf.org/html/rfc9250))
- Oblivious DNS over HTTPS ([RFC 9230](https://tools.ietf.org/html/rfc9230))

### Installation

`q` is available in binary form from:

- [apt/yum/brew from my package repositories](https://github.com/natesales/repo)
- [GitHub releases](https://github.com/natesales/q/releases)
- [q-dns-git](https://aur.archlinux.org/packages/q-dns-git/) in the AUR
- `go install github.com/natesales/q@latest`

To install `q` from source:

```sh
git clone https://github.com/natesales/q && cd q
go install

# Without debug information
go install -ldflags="-s -w -X main.version=release"
```

### Server Selection

`q` will use a server from the following sources, in order:
1. `@server` argument (e.g. `@9.9.9.9` or `@https://dns.google/dns-query`)
2. `Q_DEFAULT_SERVER` environment variable
3. `/etc/resolv.conf`

### TLS Decryption

`q` supports TLS decryption through a key log file generated when
the `SSLKEYLOGFILE` environment variable is set to the absolute path of a
writable file.

The generated file may be used by Wireshark to decipher the captured traffic.

### Feature Comparison

#### DNS Transport Protocols

| Protocol                          |  q  | doggo | dog | kdig | dig | drill |
|:----------------------------------|:---:|:-----:|:---:|:----:|:---:|:-----:|
| RFC 1034 UDP/TCP                  |  +  |   +   |  +  |  +   |  +  |   +   |
| RFC 7858 DNS over TLS             |  +  |   +   |  +  |  +   |  -  |   -   |
| RFC 8484 DNS over HTTPS           |  +  |   +   |  +  |  +   |  -  |   -   |
| RFC 9250 DNS over QUIC            |  +  |   +   |  -  |  -   |  -  |   -   |
| RFC 9230 Oblivious DNS over HTTPS |  +  |   -   |  -  |  -   |  -  |   -   |

#### Output Formats

| Format          |  q  | doggo | dog | kdig | dig | drill |
|:----------------|:---:|:-----:|:---:|:----:|:---:|:-----:|
| Raw (dig-style) |  +  |   -   |  +  |  +   |  +  |   +   |
| Pretty colors   |  +  |   +   |  +  |  -   |  -  |   -   |
| JSON            |  +  |   +   |  +  |  -   |  -  |   -   |
| YAML            |  +  |   -   |  -  |  -   |  +  |   -   |

#### Output Flags

| Option                    |  q  | doggo | dog | kdig | dig | drill |
|:--------------------------|:---:|:-----:|:---:|:----:|:---:|:-----:|
| Toggle question section   |  +  |   -   |  -  |  +   |  +  |   -   |
| Toggle answer section     |  +  |   -   |  -  |  +   |  +  |   -   |
| Toggle authority section  |  +  |   -   |  -  |  +   |  +  |   -   |
| Toggle additional section |  +  |   -   |  -  |  +   |  +  |   -   |
| Show query time           |  +  |   -   |  -  |  +   |  +  |   -   |

#### Query Flags

| Flag |  q  | doggo | dog | kdig | dig | drill |
|:-----|:---:|:-----:|:---:|:----:|:---:|:-----:|
| AA   |  +  |   -   |  +  |  +   |  +  |   +   |
| AD   |  +  |   -   |  +  |  +   |  +  |   +   |
| CD   |  +  |   -   |  +  |  +   |  +  |   +   |
| RD   |  +  |   -   |  -  |  +   |  +  |   +   |
| Z    |  +  |   -   |  -  |  +   |  +  |   -   |
| DO   |  +  |   -   |  +  |  +   |  +  |   +   |
| TC   |  +  |   -   |  -  |  +   |  +  |   +   |

#### Protocol Tweaks

| Flag                          |  q  | doggo | dog | kdig | dig | drill |
|:------------------------------|:---:|:-----:|:---:|:----:|:---:|:-----:|
| HTTP Method                   |  +  |   -   |  -  |  -   |  -  |   -   |
| QUIC ALPN Tokens              |  +  |   -   |  -  |  -   |  -  |   -   |
| QUIC toggle PMTU discovery    |  +  |   -   |  -  |  -   |  -  |   -   |
| QUIC timeouts (dial and idle) |  +  |   -   |  -  |  -   |  -  |   -   |
| TLS handshake timeout         |  +  |   -   |  -  |  -   |  -  |   -   |
