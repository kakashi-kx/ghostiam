package dashboard

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

// pageTemplates holds one compiled template set per page. Each page is parsed
// with the shared layout so {{template "content" .}} resolves to that page.
type pageTemplates struct {
	index    *template.Template
	ghosts   *template.Template
	alerts   *template.Template
	journeys *template.Template
	journey  *template.Template
	mesh     *template.Template
	seeds    *template.Template
}

// templateFuncs provides helper functions available in every template.
var templateFuncs = template.FuncMap{
	"formatTime": func(v string) string {
		if v == "" {
			return "—"
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return v
		}
		return t.Local().Format("Jan 02, 15:04:05")
	},
	"relTime": func(v string) string {
		if v == "" {
			return "—"
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return v
		}
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 24*time.Hour:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		default:
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		}
	},
	"sevBadgeClass": sevBadgeClass,
	"sevDotClass":  sevDotClass,
	"statusBadgeClass": func(s string) string {
		switch strings.ToLower(s) {
		case "active":
			return "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
		case "triggered":
			return "bg-rose-500/10 text-rose-300 border-rose-500/30"
		case "archived":
			return "bg-slate-500/10 text-slate-400 border-slate-500/30"
		default:
			return "bg-slate-500/10 text-slate-400 border-slate-500/30"
		}
	},
	"platformColor": func(p string) string {
		switch strings.ToLower(p) {
		case "aws":
			return "text-amber-300"
		case "github":
			return "text-purple-300"
		case "okta":
			return "text-sky-300"
		case "local":
			return "text-emerald-300"
		default:
			return "text-slate-300"
		}
	},
	"riskLabel": riskLabel,
	"riskPct":   riskPct,
	"trim":      strings.TrimSpace,
	"titleUpper": func(s string) string { return strings.ToUpper(s) },
}

func sevBadgeClass(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "bg-rose-500/15 text-rose-300 border border-rose-500/40"
	case "high":
		return "bg-orange-500/15 text-orange-300 border border-orange-500/40"
	case "medium":
		return "bg-amber-500/15 text-amber-300 border border-amber-500/40"
	case "low":
		return "bg-sky-500/15 text-sky-300 border border-sky-500/40"
	case "info":
		return "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40"
	default:
		return "bg-slate-500/15 text-slate-300 border border-slate-500/40"
	}
}

func sevDotClass(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "bg-rose-500"
	case "high":
		return "bg-orange-500"
	case "medium":
		return "bg-amber-500"
	case "low":
		return "bg-sky-500"
	case "info":
		return "bg-emerald-500"
	default:
		return "bg-slate-500"
	}
}

func riskLabel(score int) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func riskPct(score int) int {
	if score > 10 {
		score = 10
	}
	return score * 10
}

// loadTemplates compiles every page with the shared layout + partials.
func loadTemplates() (*pageTemplates, error) {
	pages := map[string]string{
		"index":    "templates/index.html",
		"ghosts":   "templates/ghosts.html",
		"alerts":   "templates/alerts.html",
		"journeys": "templates/journeys.html",
		"journey":  "templates/journey.html",
		"mesh":     "templates/mesh.html",
		"seeds":    "templates/seeds.html",
	}

	compile := func(page string) (*template.Template, error) {
		files := []string{
			"templates/layout.html",
			"templates/partials.html",
			pages[page],
		}
		t, err := template.New("layout").Funcs(templateFuncs).ParseFS(templateFS, files...)
		if err != nil {
			return nil, fmt.Errorf("dashboard: parse %s: %w", page, err)
		}
		return t, nil
	}

	out := &pageTemplates{}
	var err error
	if out.index, err = compile("index"); err != nil {
		return nil, err
	}
	if out.ghosts, err = compile("ghosts"); err != nil {
		return nil, err
	}
	if out.alerts, err = compile("alerts"); err != nil {
		return nil, err
	}
	if out.journeys, err = compile("journeys"); err != nil {
		return nil, err
	}
	if out.journey, err = compile("journey"); err != nil {
		return nil, err
	}
	if out.mesh, err = compile("mesh"); err != nil {
		return nil, err
	}
	if out.seeds, err = compile("seeds"); err != nil {
		return nil, err
	}
	return out, nil
}
