# q

[![Go Report](https://goreportcard.com/badge/github.com/natesales/q?style=for-the-badge)](https://goreportcard.com/report/github.com/natesales/q)
[![License](https://img.shields.io/github/license/natesales/q?style=for-the-badge)](https://raw.githubusercontent.com/natesales/q/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/natesales/q?style=for-the-badge)](https://github.com/natesales/q/releases)

A tiny CLI DNS client library with support for UDP, DoT, DoH, and DoQ.

## Usage
```bash
q CLI DNS client (https://github.com/natesales/q)

Usage:
  q @<protocol>://<server>:[port] <rr types> <qname> [OPTIONS]

Options:
  -d, --dnssec  Request DNSSEC
  -r, --raw     Output raw DNS string format
  -h, --help    Display help menu
  -v, --verbose Enable verbose logging
  -q, --quiet   Don't display DNS response

Protocols:
  dns    RFC 1034 UDP/TCP DNS
  tls    RFC 7858 DNS over TLS
  https  RFC 8484 DNS over HTTPS
  quic   draft-ietf-dprive-dnsoquic-02 DNS over QUIC
```
