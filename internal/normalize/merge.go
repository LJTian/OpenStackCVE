package normalize

import (
	"sort"
	"strings"
	"time"

	"OpenStackCVE/internal/model"
)

// MergeCVE deduplicates by cve_id semantics: union lists, fill blanks, prefer OSSA prose.
func MergeCVE(existing, incoming model.CVE) model.CVE {
	out := existing

	if incoming.CVEID != "" {
		out.CVEID = strings.ToUpper(incoming.CVEID)
	}

	out.Title = preferText(existing.Title, incoming.Title, existing.Source, incoming.Source)
	out.Summary = preferText(existing.Summary, incoming.Summary, existing.Source, incoming.Source)
	out.Components = unionFold(existing.Components, incoming.Components)
	out.Refs = unionExact(existing.Refs, incoming.Refs)
	out.Source = joinSources(existing.Source, incoming.Source)

	if strings.TrimSpace(existing.Severity) != "" {
		out.Severity = strings.ToLower(strings.TrimSpace(existing.Severity))
	} else {
		out.Severity = strings.ToLower(strings.TrimSpace(incoming.Severity))
	}

	out.PublishedAt = earlierTime(existing.PublishedAt, incoming.PublishedAt)
	if incoming.FetchedAt.After(existing.FetchedAt) {
		out.FetchedAt = incoming.FetchedAt
	}
	return out
}

func preferText(a, b, sourceA, sourceB string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	aOSSA := strings.Contains(strings.ToLower(sourceA), "ossa")
	bOSSA := strings.Contains(strings.ToLower(sourceB), "ossa")
	if aOSSA && !bOSSA {
		return a
	}
	if bOSSA && !aOSSA {
		return b
	}
	if len(b) > len(a) {
		return b
	}
	return a
}

func joinSources(a, b string) string {
	seen := map[string]struct{}{}
	var parts []string
	add := func(s string) {
		for _, p := range strings.Split(s, ",") {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			parts = append(parts, p)
		}
	}
	add(a)
	add(b)
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func unionFold(a, b []string) []string {
	seen := map[string]string{}
	add := func(items []string) {
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			key := strings.ToLower(item)
			if _, ok := seen[key]; !ok {
				seen[key] = item
			}
		}
	}
	add(a)
	add(b)
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func unionExact(a, b []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(items []string) {
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	add(a)
	add(b)
	return out
}

func earlierTime(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.Before(*a) {
		return b
	}
	return a
}
