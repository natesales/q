package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMainNXDOMAIN(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        conn,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
			reply := new(dns.Msg).SetReply(query)
			switch query.Question[0].Name {
			case "missing.example.":
				reply.Rcode = dns.RcodeNameError
			case "present.example.":
				reply.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: "present.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 1),
				}}
			}
			assert.NoError(t, w.WriteMsg(reply))
		}),
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-serverErr:
		conn.Close()
		t.Fatalf("start DNS fixture: %v", err)
	}
	t.Cleanup(func() {
		assert.NoError(t, server.Shutdown())
		assert.NoError(t, <-serverErr)
	})

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{name: "default queries", args: []string{"missing.example."}, want: "missing.example. NXDOMAIN\n"},
		{name: "short", args: []string{"missing.example.", "--short"}},
		{name: "column", args: []string{"missing.example.", "--format=column"}},
		{name: "empty NOERROR", args: []string{"empty.example.", "A"}},
		{name: "positive answer", args: []string{"present.example.", "A", "+nopretty-ttls"}, want: "present.example. 60 A 192.0.2.1\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"@" + conn.LocalAddr().String(), "--timeout=2s"}, tt.args...)
			out, err := run(args...)
			require.NoError(t, err)
			assert.Equal(t, tt.want, out.String())
		})
	}

	for _, format := range []string{"json", "yaml", "raw"} {
		t.Run(format, func(t *testing.T) {
			out, err := run("@"+conn.LocalAddr().String(), "missing.example.", "A", "--format="+format, "--timeout=2s")
			require.NoError(t, err)
			if format == "raw" {
				assert.Contains(t, out.String(), "status: NXDOMAIN")
				assert.Equal(t, 1, strings.Count(out.String(), "NXDOMAIN"))
				return
			}
			var entries []struct{ Replies []dns.Msg }
			if format == "json" {
				err = json.Unmarshal(out.Bytes(), &entries)
			} else {
				err = yaml.Unmarshal(out.Bytes(), &entries)
			}
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Len(t, entries[0].Replies, 1)
			assert.Equal(t, dns.RcodeNameError, entries[0].Replies[0].Rcode)
		})
	}
}
