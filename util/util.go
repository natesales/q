package util

import (
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"
)

var UseColor = true

// ANSI colors
var colors = map[string]string{
	"black":   "\033[1;30m%s\033[0m",
	"red":     "\033[1;31m%s\033[0m",
	"green":   "\033[1;32m%s\033[0m",
	"yellow":  "\033[1;33m%s\033[0m",
	"purple":  "\033[1;34m%s\033[0m",
	"magenta": "\033[1;35m%s\033[0m",
	"teal":    "\033[1;36m%s\033[0m",
	"white":   "\033[1;37m%s\033[0m",
}

// Color returns a color formatted string
func Color(color string, args ...interface{}) string {
	if _, ok := colors[color]; !ok {
		panic("invalid color: " + color)
	}

	if UseColor {
		return fmt.Sprintf(colors[color], fmt.Sprint(args...))
	} else {
		return fmt.Sprint(args...)
	}
}

func ContainsAny(s string, subStrings []string) bool {
	for _, sub := range subStrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func MustWriteln(out io.Writer, s string) {
	if _, err := out.Write([]byte(s + "\n")); err != nil {
		log.Fatal(err)
	}
}

func MustWritef(out io.Writer, format string, a ...interface{}) {
	if _, err := out.Write([]byte(fmt.Sprintf(format, a...))); err != nil {
		log.Fatal(err)
	}
}
