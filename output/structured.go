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

func (p Printer) PrintStructured(entries []*Entry) {
	out := make([]reply, 0)
	for _, entry := range entries {
		for _, r := range entry.Replies {
			out = append(out, reply{
				Server:    entry.Server,
				QueryTime: int64(entry.Time.Round(time.Millisecond)),
				Answers:   r.Answer,
				ID:        r.Id,
				Truncated: r.Truncated,
			})
		}
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
