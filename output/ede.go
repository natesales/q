package output

import (
	"fmt"

	"github.com/miekg/dns"
)

type edeInfo struct {
	Code uint16
	Text string
}

// extractEDE returns any Extended DNS Errors (RFC 8914) present in the message.
func extractEDE(m *dns.Msg) []edeInfo {
	var out []edeInfo
	if m == nil {
		return out
	}
	opt := m.IsEdns0()
	if opt == nil {
		return out
	}
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0EDE {
			if e, ok := o.(*dns.EDNS0_EDE); ok {
				out = append(out, edeInfo{Code: e.InfoCode, Text: e.ExtraText})
			}
		}
	}
	return out
}

func edeName(code uint16) string {
	if s, ok := dns.ExtendedErrorCodeToString[code]; ok {
		return s
	}
	return fmt.Sprintf("Unknown EDE code: %d", code)
}
