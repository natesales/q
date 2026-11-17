package registry

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openrdap/rdap"
)

// formatRDAPPretty renders an RDAP response in whois-style key:value form for
// all four topmost object types (Domain, IPNetwork, Autnum, Entity). Returns
// an empty string if the object type isn't recognized
func formatRDAPPretty(resp *rdap.Response) string {
	switch v := resp.Object.(type) {
	case *rdap.Domain:
		return prettyDomain(v)
	case *rdap.IPNetwork:
		return prettyIPNetwork(v)
	case *rdap.Autnum:
		return prettyAutnum(v)
	case *rdap.Entity:
		return prettyEntity(v)
	}
	return ""
}

// kvBuilder accumulates aligned key:value lines and emits them with a
// consistent column width.
type kvBuilder struct {
	sections [][]kvLine
	current  []kvLine
}

type kvLine struct {
	key, value string
}

func (b *kvBuilder) add(key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	b.current = append(b.current, kvLine{key, value})
}

func (b *kvBuilder) addMulti(key string, values []string) {
	for _, v := range values {
		b.add(key, v)
	}
}

// section closes the current group of lines so the next add starts a fresh
// visual section. Empty sections are dropped
func (b *kvBuilder) section() {
	if len(b.current) > 0 {
		b.sections = append(b.sections, b.current)
		b.current = nil
	}
}

func (b *kvBuilder) String() string {
	b.section()
	if len(b.sections) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, s := range b.sections {
		if i > 0 {
			sb.WriteByte('\n')
		}
		width := 0
		for _, l := range s {
			if n := len(l.key); n > width {
				width = n
			}
		}
		width++ // for the colon
		for _, l := range s {
			fmt.Fprintf(&sb, "%-*s %s\n", width, l.key+":", l.value)
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func eventDate(events []rdap.Event, action string) string {
	for _, e := range events {
		if strings.EqualFold(e.Action, action) {
			return e.Date
		}
	}
	return ""
}

func prettyDomain(d *rdap.Domain) string {
	var b kvBuilder
	name := d.LDHName
	if name == "" {
		name = d.UnicodeName
	}
	b.add("Domain Name", strings.ToUpper(name))
	b.add("Handle", d.Handle)
	b.add("Status", strings.Join(d.Status, ", "))
	b.add("Registration", eventDate(d.Events, "registration"))
	b.add("Expiration", eventDate(d.Events, "expiration"))
	b.add("Last Changed", eventDate(d.Events, "last changed"))
	b.add("Port43", d.Port43)

	for _, ns := range d.Nameservers {
		nsName := ns.LDHName
		if nsName == "" {
			nsName = ns.UnicodeName
		}
		b.add("Name Server", strings.ToUpper(nsName))
	}

	if d.SecureDNS != nil && d.SecureDNS.DelegationSigned != nil {
		b.add("DNSSEC", boolStr(*d.SecureDNS.DelegationSigned, "signedDelegation", "unsigned"))
	}

	for _, e := range d.Entities {
		appendEntity(&b, &e)
	}
	return b.String()
}

func prettyIPNetwork(n *rdap.IPNetwork) string {
	var b kvBuilder
	if n.StartAddress != "" || n.EndAddress != "" {
		b.add("NetRange", strings.TrimSpace(fmt.Sprintf("%s - %s", n.StartAddress, n.EndAddress)))
	}
	b.add("Handle", n.Handle)
	b.add("NetName", n.Name)
	b.add("NetType", n.Type)
	b.add("Country", n.Country)
	b.add("ParentHandle", n.ParentHandle)
	b.add("IPVersion", n.IPVersion)
	b.add("Status", strings.Join(n.Status, ", "))
	b.add("Registration", eventDate(n.Events, "registration"))
	b.add("Last Changed", eventDate(n.Events, "last changed"))
	b.add("Port43", n.Port43)

	for _, e := range n.Entities {
		appendEntity(&b, &e)
	}
	return b.String()
}

func prettyAutnum(a *rdap.Autnum) string {
	var b kvBuilder
	if a.StartAutnum != nil {
		if a.EndAutnum != nil && *a.EndAutnum != *a.StartAutnum {
			b.add("ASRange", fmt.Sprintf("AS%d - AS%d", *a.StartAutnum, *a.EndAutnum))
		} else {
			b.add("ASNumber", fmt.Sprintf("AS%d", *a.StartAutnum))
		}
	}
	b.add("ASName", a.Name)
	b.add("Handle", a.Handle)
	b.add("Type", a.Type)
	b.add("Country", a.Country)
	b.add("Status", strings.Join(a.Status, ", "))
	b.add("Registration", eventDate(a.Events, "registration"))
	b.add("Last Changed", eventDate(a.Events, "last changed"))
	b.add("Port43", a.Port43)

	for _, e := range a.Entities {
		appendEntity(&b, &e)
	}
	return b.String()
}

func prettyEntity(e *rdap.Entity) string {
	var b kvBuilder
	appendEntity(&b, e)
	return b.String()
}

// appendEntity writes a vCard-derived block (org, name, address, contact info)
// for a single Entity. Each entity becomes its own visual section.
// https://www.arin.net/resources/registry/whois/rdap/
func appendEntity(b *kvBuilder, e *rdap.Entity) {
	b.section()

	roles := strings.Join(e.Roles, ", ")
	if roles == "" {
		roles = "Entity"
	}
	header := strings.ToUpper(roles[:1]) + roles[1:]
	b.add(header, e.Handle)

	if e.VCard != nil {
		v := e.VCard
		if org := vcardOrg(v); org != "" {
			b.add("Organization", org)
		}
		b.add("Name", v.Name())
		if street := v.StreetAddress(); street != "" {
			b.add("Address", street)
		}
		if poBox := v.POBox(); poBox != "" {
			b.add("PO Box", poBox)
		}
		if ext := v.ExtendedAddress(); ext != "" {
			b.add("Address Line", ext)
		}
		b.add("City", v.Locality())
		b.add("State/Province", v.Region())
		b.add("Postal Code", v.PostalCode())
		b.add("Country", v.Country())
		b.add("Phone", v.Tel())
		b.add("Fax", v.Fax())
		b.add("Email", v.Email())
	}
	b.add("Status", strings.Join(e.Status, ", "))
	b.add("Registration", eventDate(e.Events, "registration"))
	b.add("Last Changed", eventDate(e.Events, "last changed"))

	// Public IDs belong to this entity. Emit them before descending so they
	// stay in this section instead of the last child's.
	if len(e.PublicIDs) > 0 {
		ids := make([]string, 0, len(e.PublicIDs))
		for _, id := range e.PublicIDs {
			ids = append(ids, fmt.Sprintf("%s=%s", id.Type, id.Identifier))
		}
		sort.Strings(ids)
		b.addMulti("Public ID", ids)
	}

	for _, child := range e.Entities {
		appendEntity(b, &child)
	}
}

// vcardOrg pulls the first "org" property out of a vCard, joining multi-value
// org strings with " / ".
func vcardOrg(v *rdap.VCard) string {
	p := v.GetFirst("org")
	if p == nil {
		return ""
	}
	return strings.Join(p.Values(), " / ")
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
