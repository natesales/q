package cli

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

// CompletionScript returns a completion script for the given shell covering all options of parser
func CompletionScript(shell string, parser *flags.Parser) (string, error) {
	var options []*flags.Option
	for _, o := range groupOptions(parser.Command.Group) {
		if !o.Hidden {
			options = append(options, o)
		}
	}

	switch shell {
	case "bash":
		return bashCompletion(options), nil
	case "zsh":
		return zshCompletion(options), nil
	case "fish":
		return fishCompletion(options), nil
	}
	return "", fmt.Errorf("unsupported shell %q", shell)
}

func groupOptions(g *flags.Group) []*flags.Option {
	options := g.Options()
	for _, sub := range g.Groups() {
		options = append(options, groupOptions(sub)...)
	}
	return options
}

// isBoolOption reports whether o is a switch that takes no value, mirroring go-flags
func isBoolOption(o *flags.Option) bool {
	t := reflect.TypeOf(o.Value())
	for t.Kind() == reflect.Slice || t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind() == reflect.Bool || (t.Kind() == reflect.Func && t.NumIn() == 0)
}

func isSliceOption(o *flags.Option) bool {
	return reflect.TypeOf(o.Value()).Kind() == reflect.Slice
}

// plusFlags returns the +flag and +noflag toggles accepted by ParsePlusFlags
func plusFlags(options []*flags.Option) []string {
	var toggles []string
	for _, o := range options {
		if _, ok := o.Value().(bool); !ok || o.LongName == "" {
			continue
		}
		// ParsePlusFlags ignores toggles of 3 characters or fewer and reads a leading "no" as negation
		if on := "+" + o.LongName; len(on) > 3 && !strings.HasPrefix(o.LongName, "no") {
			toggles = append(toggles, on)
		}
		toggles = append(toggles, "+no"+o.LongName)
	}
	return toggles
}

// rrTypes returns the RR type names accepted as positional arguments
func rrTypes() []string {
	var types []string
	for name := range dns.StringToType {
		// Skips pseudo entries such as "None" and "Reserved"
		if name == strings.ToUpper(name) {
			types = append(types, name)
		}
	}
	slices.Sort(types)
	return types
}

func optionNames(o *flags.Option) []string {
	var names []string
	if o.ShortName != 0 {
		names = append(names, "-"+string(o.ShortName))
	}
	if o.LongName != "" {
		names = append(names, "--"+o.LongName)
	}
	return names
}

func bashCompletion(options []*flags.Option) string {
	var names, valueNames []string
	var choiceCases strings.Builder
	for _, o := range options {
		names = append(names, optionNames(o)...)
		switch {
		case len(o.Choices) > 0:
			fmt.Fprintf(&choiceCases, "    %s)\n      COMPREPLY=($(compgen -W %q -- \"$cur\"))\n      return\n      ;;\n",
				strings.Join(optionNames(o), "|"), strings.Join(o.Choices, " "))
		case !isBoolOption(o):
			valueNames = append(valueNames, optionNames(o)...)
		}
	}

	return fmt.Sprintf(`# bash completion for q

_q() {
  local cur prev flag
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  flag="$prev"

  # bash splits --flag=value into separate words at the "="
  if [[ "$cur" == "=" ]]; then
    cur=""
  elif [[ "$prev" == "=" ]]; then
    flag="${COMP_WORDS[COMP_CWORD-2]}"
  fi

  case "$flag" in
%s    %s)
      compopt -o default
      COMPREPLY=()
      return
      ;;
  esac

  case "$cur" in
    -*) COMPREPLY=($(compgen -W %q -- "$cur")) ;;
    +*) COMPREPLY=($(compgen -W %q -- "$cur")) ;;
    *) COMPREPLY=($(compgen -W %q -- "$cur")) ;;
  esac
}

complete -F _q q
`, choiceCases.String(), strings.Join(valueNames, "|"), strings.Join(names, " "),
		strings.Join(plusFlags(options), " "), strings.Join(rrTypes(), " "))
}

func zshCompletion(options []*flags.Option) string {
	descEscaper := strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`, `'`, `'\''`)

	var specs strings.Builder
	for _, o := range options {
		repeat := ""
		if isSliceOption(o) {
			repeat = "*"
		}
		arg := ""
		if !isBoolOption(o) {
			arg = ":value:"
			if len(o.Choices) > 0 {
				arg += "(" + strings.Join(o.Choices, " ") + ")"
			}
		}
		for _, name := range optionNames(o) {
			if arg != "" {
				if strings.HasPrefix(name, "--") {
					name += "="
				} else {
					name += "+"
				}
			}
			fmt.Fprintf(&specs, "    '%s%s[%s]%s' \\\n", repeat, name, descEscaper.Replace(o.Description), arg)
		}
	}

	return fmt.Sprintf(`#compdef q

_q() {
  local context state state_descr line
  typeset -A opt_args
  local -a rrtypes plusflags
  rrtypes=(%s)
  plusflags=(%s)

  _arguments -s \
%s    '*: :->args'

  case $state in
    args) compadd -a rrtypes plusflags ;;
  esac
}

if [ "$funcstack[1]" = "_q" ]; then
  _q "$@"
else
  compdef _q q
fi
`, strings.Join(rrTypes(), " "), strings.Join(plusFlags(options), " "), specs.String())
}

func fishCompletion(options []*flags.Option) string {
	quote := func(s string) string {
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}

	var b strings.Builder
	b.WriteString("# fish completion for q\n\ncomplete -c q -f\n")
	for _, o := range options {
		b.WriteString("complete -c q")
		if o.ShortName != 0 {
			fmt.Fprintf(&b, " -s %c", o.ShortName)
		}
		if o.LongName != "" {
			fmt.Fprintf(&b, " -l %s", o.LongName)
		}
		switch {
		case len(o.Choices) > 0:
			fmt.Fprintf(&b, " -x -a %s", quote(strings.Join(o.Choices, " ")))
		case !isBoolOption(o):
			b.WriteString(" -r -F")
		}
		fmt.Fprintf(&b, " -d %s\n", quote(o.Description))
	}
	fmt.Fprintf(&b, "complete -c q -a %s\n", quote(strings.Join(plusFlags(options), " ")))
	fmt.Fprintf(&b, "complete -c q -a %s -d 'RR type'\n", quote(strings.Join(rrTypes(), " ")))
	return b.String()
}
