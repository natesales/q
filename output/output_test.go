package output

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// replies returns a slice of example DNS answer messages
func replies() []*dns.Msg {
	testZone := `
example.com. 86400 IN A 192.0.2.1
example.com. 86400 IN A 192.0.2.2
example.com. 86400 IN NS b.iana-servers.net.
example.com. 86400 IN NS a.iana-servers.net.
example.com. 86400 IN MX 0 .
example.com. 86400 IN TXT "v=spf1 -all"
`

	// Convert the zone to DNS messages
	var msgs []*dns.Msg
	for _, line := range strings.Split(testZone, "\n") {
		if line != "" {
			rr, err := dns.NewRR(line)
			if err != nil {
				panic(err)
			}
			msgs = append(msgs, &dns.Msg{Answer: []dns.RR{rr}})
		}
	}

	return msgs
}

var entries = []*Entry{
	{
		Replies:     replies(),
		Server:      "192.0.2.10",
		Time:        time.Second * 2,
		Txp:         nil,
		PTRs:        nil,
		existingRRs: nil,
	},
}
