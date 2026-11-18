package normalize

import (
	"encoding/json"
	"strings"
	"time"

	"OpenStackCVE/internal/model"
)

// FromAdvisory expands one OSSA advisory into zero or more CVE rows.
// Advisories without CVE IDs yield an empty slice.
func FromAdvisory(adv *model.Advisory, source string, fetchedAt time.Time) ([]model.CVE, string, error) {
	if adv == nil {
		return nil, "", nil
	}
	rawBytes, err := json.Marshal(adv)
	if err != nil {
		return nil, "", err
	}
	raw := string(rawBytes)

	components := ComponentsFromAffects(adv.Affects)
	refs := RefsFromAdvisory(adv)
	published := ParsePublishedAt(adv.Date)

	var out []model.CVE
	for _, id := range adv.CVEs {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		out = append(out, model.CVE{
			CVEID:       id,
			Title:       adv.Title,
			Summary:     adv.Description,
			Components:  append([]string(nil), components...),
			Severity:    "",
			PublishedAt: published,
			Refs:        append([]string(nil), refs...),
			Source:      source,
			FetchedAt:   fetchedAt,
		})
	}
	return out, raw, nil
}

// ComponentsFromAffects extracts component names from "Nova: <versions>" lines.
func ComponentsFromAffects(affects []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, line := range affects {
		name := strings.TrimSpace(line)
		if i := strings.Index(name, ":"); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	if out == nil {
		return []string{}
	}
	return out
}

// RefsFromAdvisory collects patch and reference URLs.
func RefsFromAdvisory(adv *model.Advisory) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	for _, p := range adv.Patches {
		add(p.URL)
	}
	for _, r := range adv.References {
		add(r)
	}
	if adv.SourceURL != "" {
		add(adv.SourceURL)
	}
	if out == nil {
		return []string{}
	}
	return out
}

// ParsePublishedAt parses OSSA date strings like "November 17, 2026".
func ParsePublishedAt(date string) *time.Time {
	date = strings.TrimSpace(date)
	if date == "" {
		return nil
	}
	layouts := []string{
		"January 2, 2006",
		"Jan 2, 2006",
		"2006-01-02",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, date); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}
