package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOutputPrettyPTRCache(t *testing.T) {
	p := Printer{}
	p.ptrCache = make(map[string]string)

	p.ptrCache["192.0.2.1"] = "example.com."

	ptr, err := p.ptr("192.0.2.1")
	assert.Nil(t, err)
	assert.Equal(t, "example.com.", ptr)
}
