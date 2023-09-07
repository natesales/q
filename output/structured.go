package output

import (
	"encoding/json"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/natesales/q/util"
)

func (p Printer) PrintStructured(i int, reply *dns.Msg) {
	body := struct {
		Server    string
		QueryTime int64
		Answers   []dns.RR
		ID        uint16
		Truncated bool
	}{
		Server:    p.Server,
		QueryTime: int64(p.QueryTime.Round(time.Millisecond)),
		Answers:   reply.Answer,
		ID:        reply.Id,
		Truncated: reply.Truncated,
	}
	var b []byte
	var err error
	if p.Opts.Format == "json" {
		b, err = json.Marshal(body)
	} else { // yaml
		b, err = yaml.Marshal(body)
	}
	if err != nil {
		log.Fatalf("error marshaling output: %s", err)
	}

	util.MustWriteln(p.Out, string(b))
}
