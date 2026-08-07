package journey

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ToMermaid renders the attack graph as Mermaid.js flowchart syntax.
func ToMermaid(g *AttackGraph) string {
	var b strings.Builder
	b.WriteString("graph TD\n")
	for _, n := range g.Nodes {
		b.WriteString(fmt.Sprintf("    %s[%s<br/>%s]\n", n.ID, n.FQN(), strings.ToUpper(n.Severity)))
	}
	for _, e := range g.Edges {
		b.WriteString(fmt.Sprintf("    %s --> %s\n", e.From, e.To))
	}
	for _, n := range g.Nodes {
		color := "#f9f9ff"
		switch n.Severity {
		case "data-access":
			color = "#ff9999"
		case "exfiltration":
			color = "#ff0000"
		case "privilege-escalation":
			color = "#ffcc66"
		case "lateral-movement":
			color = "#ff7f50"
		}
		b.WriteString(fmt.Sprintf("    style %s fill:%s,stroke:#333\n", n.ID, color))
	}
	return b.String()
}

// MermaidImageURL converts a Mermaid diagram into a mermaid.ink render URL that
// can be embedded in a Slack image block or message link.
func MermaidImageURL(mermaid string) string {
	return "https://mermaid.ink/img/" + base64.RawURLEncoding.EncodeToString([]byte(mermaid))
}
