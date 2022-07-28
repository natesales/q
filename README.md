<div align="center">
<h1>q</h1>

A tiny and feature-rich command line DNS client with support for UDP, TCP, DoT, DoH, DoQ, and ODoH.

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
  -q, --qname=             Query name
  -s, --server=            DNS server
  -t, --type=              RR type (e.g. A, AAAA, MX, etc.) or type integer
  -x, --reverse            Reverse lookup
  -d, --dnssec             Set the DO (DNSSEC OK) bit in the OPT record
  -n, --nsid               Set EDNS0 NSID opt
      --subnet=            Set EDNS0 client subnet
  -c, --chaos              Use CHAOS query class
  -p, --odoh-proxy=        ODoH proxy
      --timeout=           Query timeout in seconds (default: 10)
      --pad                Set EDNS0 padding
  -f, --format=            Output format (pretty, json, yaml, raw) (default:
                           pretty)
      --pretty-ttls        Format TTLs in human readable format (default: true)
      --color              Enable color output
      --question           Show question section
      --answer             Show answer section (default: true)
      --authority          Show authority section
      --additional         Show additional section
      --stats              Show time statistics
      --all                Show all sections and statistics
      --aa                 Set AA (Authoritative Answer) flag in query
      --ad                 Set AD (Authentic Data) flag in query
      --cd                 Set CD (Checking Disabled) flag in query
      --rd                 Set RD (Recursion Desired) flag in query (default:
                           true)
      --ra                 Set RA (Recursion Available) flag in query
      --z                  Set Z (Zero) flag in query
      --t                  Set TC (Truncated) flag in query
  -i, --tls-no-verify      Disable TLS certificate verification
      --tls-min-version=   Minimum TLS version to use (default: 1.0)
      --tls-max-version=   Maximum TLS version to use (default: 1.3)
      --http-user-agent=   HTTP user agent
      --http-method=       HTTP method (default: GET)
      --quic-alpn-tokens=  QUIC ALPN tokens (default: doq, doq-i11)
      --quic-keep-alive    QUIC keep-alive
      --quic-no-pmtud      Disable QUIC PMTU discovery
      --quic-dial-timeout= QUIC dial timeout (default: 10)
      --quic-idle-timeout= QUIC stream open timeout (default: 10)
      --handshake-timeout= Handshake timeout (default: 10)
      --udp-buffer=        Set EDNS0 UDP size in query (default: 1232)
  -v, --verbose            Show verbose log messages
  -V, --version            Show version and exit

Help Options:
  -h, --help               Show this help message
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
* [my public package repositories](https://github.com/natesales/repo),
* [GitHub releases](https://github.com/natesales/q/releases),
* and the AUR as [q-dns-git](https://aur.archlinux.org/packages/q-dns-git/)

To install `q` from source do:  
```sh
git clone https://github.com/natesales/q && cd q
go install

# without debug information
go install -ldflags="-s -w -X main.version=release"
```

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
| QUIC Keepalive                |  +  |   -   |  -  |  -   |  -  |   -   |
| QUIC toggle PMTU discovery    |  +  |   -   |  -  |  -   |  -  |   -   |
| QUIC timeouts (dial and idle) |  +  |   -   |  -  |  -   |  -  |   -   |
| TLS handshake timeout         |  +  |   -   |  -  |  -   |  -  |   -   |
