package util

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUtilContainsAny(t *testing.T) {
	assert.True(t, ContainsAny("foo", []string{"foo", "bar"}))
	assert.True(t, ContainsAny("bar", []string{"foo", "bar"}))
	assert.False(t, ContainsAny("baz", []string{"foo", "bar"}))
}

func TestUtilMustWriteln(t *testing.T) {
	var out bytes.Buffer
	MustWriteln(&out, "foo")
	assert.Equal(t, "foo\n", out.String())
}

func TestUtilMustWritef(t *testing.T) {
	var out bytes.Buffer
	MustWritef(&out, "foo %s", "bar")
	assert.Equal(t, "foo bar", out.String())
}

func TestUtilColor(t *testing.T) {
	assert.Equal(t, "\033[1;31mfoo\033[0m", Color("red", "foo"))
	assert.Equal(t, "\033[1;37mfoo\033[0m", Color("white", "foo"))
}
