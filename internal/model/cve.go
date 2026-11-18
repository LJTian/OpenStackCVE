package model

import "time"

// CVE is the normalized record stored in SQLite and returned by query.
type CVE struct {
	CVEID       string     `json:"cve_id"`
	Title       string     `json:"title"`
	Summary     string     `json:"summary"`
	Components  []string   `json:"components"`
	Severity    string     `json:"severity"`
	PublishedAt *time.Time `json:"published_at"`
	Refs        []string   `json:"refs"`
	Source      string     `json:"source"`
	FetchedAt   time.Time  `json:"fetched_at"`
}

// QueryResult is the stdout JSON envelope for the query command.
type QueryResult struct {
	Count int   `json:"count"`
	Items []CVE `json:"items"`
}

// Advisory is the raw OSSA page parse result before CVE normalization.
type Advisory struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Date        string   `json:"date"`
	CVEs        []string `json:"cves"`
	Affects     []string `json:"affects"`
	Description string   `json:"description"`
	Patches     []Patch  `json:"patches"`
	Credits     []string `json:"credits"`
	References  []string `json:"references"`
	Notes       []string `json:"notes"`
	SourceURL   string   `json:"source_url"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

// Patch links a review URL to a release branch.
type Patch struct {
	URL     string `json:"url"`
	Release string `json:"release,omitempty"`
}
