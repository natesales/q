package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/util"
)

func TestOutputPrettyPTRCache(t *testing.T) {
	p := Printer{}
	p.ptrCache = make(map[string]string)

	p.ptrCache["192.0.2.1"] = "example.com."

	ptr, err := p.ptr("192.0.2.1")
	assert.Nil(t, err)
	assert.Equal(t, "example.com.", ptr)
}

func TestOutputPrettyPrintColumn(t *testing.T) {
	var buf bytes.Buffer
	util.UseColor = false
	p := Printer{Out: &buf, Opts: &cli.Flags{Format: "column"}}
	p.PrintColumn(replies())
	assert.Contains(t, buf.String(), `A 86400 192.0.2.2`)
	assert.Contains(t, buf.String(), `MX 86400 0 .`)
	assert.Contains(t, buf.String(), `NS 86400 a.iana-servers.net.`)
	assert.Contains(t, buf.String(), `NS 86400 b.iana-servers.net.`)
	assert.Contains(t, buf.String(), `TXT 86400 "v=spf1 -all"`)
}
