package output

import (
	"io"
	"time"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/transport"
)

type Printer struct {
	Out        io.Writer
	Opts       *cli.Flags
	QueryTime  time.Duration
	Server     string
	NumReplies int

	// Transport is used to resolve IP addresses in A/AAAA records to their PTR records
	Transport *transport.Transport

	ptrCache    map[string]string // IP -> PTR value
	existingRRs map[string]bool

	// Longest string lengths for column formatting
	longestTTL    int
	longestRRType int
}
