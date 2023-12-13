package output

import (
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/natesales/q/util"
)

func (p Printer) PrintStructured(entries []*Entry) {
	var marshaler func(any) ([]byte, error)
	if p.Opts.Format == "json" {
		extra.SetNamingStrategy(strings.ToLower)
		json := jsoniter.ConfigCompatibleWithStandardLibrary
		marshaler = json.Marshal
	} else { // yaml
		marshaler = yaml.Marshal
	}

	b, err := marshaler(entries)
	if err != nil {
		log.Fatalf("error marshaling output: %s", err)
	}

	util.MustWriteln(p.Out, string(b))
}
