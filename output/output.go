package output

import (
	"io"
	"time"

	"github.com/natesales/q/cli"
)

type Printer struct {
	Out        io.Writer
	Opts       *cli.Flags
	QueryTime  time.Duration
	Server     string
	NumReplies int

	existingRRs map[string]bool
}
