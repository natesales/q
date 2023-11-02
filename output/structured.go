package output

import (
	"encoding/json"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/natesales/q/util"
)

type reply struct {
	Server    string
	QueryTime int64
	Answers   []dns.RR
	ID        uint16
	Truncated bool
}

func (p Printer) PrintStructured(replies []*dns.Msg) {
	out := make([]reply, len(replies))
	for _, r := range replies {
		out = append(out, reply{
			Server:    p.Server,
			QueryTime: int64(p.QueryTime.Round(time.Millisecond)),
			Answers:   r.Answer,
			ID:        r.Id,
			Truncated: r.Truncated,
		})
	}

	var b []byte
	var err error
	if p.Opts.Format == "json" {
		b, err = json.Marshal(out)
	} else { // yaml
		b, err = yaml.Marshal(out)
	}
	if err != nil {
		log.Fatalf("error marshaling output: %s", err)
	}

	util.MustWriteln(p.Out, string(b))
}
