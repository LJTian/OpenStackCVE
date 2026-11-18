package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"OpenStackCVE/internal/model"
)

const (
	defaultNVDAPI   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdPageSize     = 2000
	nvdMinInterval  = 7 * time.Second // stay under public rate limit without API key
	maxNVDAttempts  = 5
)

// NVDClient fetches OpenStack-related CVEs from NVD API 2.0.
type NVDClient struct {
	HTTP    *http.Client
	APIBase string
	APIKey  string
	Keyword string
}

// NewNVD builds a client. API key may come from arg or NVD_API_KEY env.
func NewNVD(apiBase, apiKey, keyword string) *NVDClient {
	if apiBase == "" {
		apiBase = defaultNVDAPI
	}
	if apiKey == "" {
		apiKey = os.Getenv("NVD_API_KEY")
	}
	if keyword == "" {
		keyword = "OpenStack"
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
	}
	return &NVDClient{
		HTTP:    &http.Client{Timeout: 120 * time.Second, Transport: transport},
		APIBase: strings.TrimRight(apiBase, "/"),
		APIKey:  apiKey,
		Keyword: keyword,
	}
}

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CVSSMetricV31 []struct {
			CVSSData struct {
				BaseSeverity string  `json:"baseSeverity"`
				BaseScore    float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CVSSMetricV30 []struct {
			CVSSData struct {
				BaseSeverity string `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
		CVSSMetricV2 []struct {
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []struct {
		Nodes []nvdNode `json:"nodes"`
	} `json:"configurations"`
}

type nvdNode struct {
	CPEMatch []struct {
		Criteria string `json:"criteria"`
	} `json:"cpeMatch"`
	Operators string    `json:"operator"`
	Children  []nvdNode `json:"children"`
}

// FetchOpenStack pulls NVD CVEs for the lookback window and normalizes them.
// NVD requires date windows of at most 120 consecutive days.
func (c *NVDClient) FetchOpenStack(lookbackDays int, fetchedAt time.Time) ([]model.CVE, []string, error) {
	if lookbackDays <= 0 {
		lookbackDays = 1825
	}
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -lookbackDays)

	seen := map[string]struct{}{}
	var (
		out  []model.CVE
		raws []string
	)

	for windowStart := start; windowStart.Before(end); {
		windowEnd := windowStart.AddDate(0, 0, 120)
		if windowEnd.After(end) {
			windowEnd = end
		}
		log.Printf("nvd window %s .. %s", windowStart.Format("2006-01-02"), windowEnd.Format("2006-01-02"))

		startIndex := 0
		for {
			page, err := c.fetchPage(windowStart, windowEnd, startIndex)
			if err != nil {
				return nil, nil, err
			}
			for _, item := range page.Vulnerabilities {
				cve, raw, ok := normalizeNVD(item.CVE, fetchedAt)
				if !ok {
					continue
				}
				if _, ok := seen[cve.CVEID]; ok {
					continue
				}
				seen[cve.CVEID] = struct{}{}
				out = append(out, cve)
				raws = append(raws, raw)
			}
			log.Printf("nvd page startIndex=%d got=%d total=%d kept_so_far=%d",
				startIndex, len(page.Vulnerabilities), page.TotalResults, len(out))

			startIndex += page.ResultsPerPage
			if startIndex >= page.TotalResults || page.ResultsPerPage == 0 || len(page.Vulnerabilities) == 0 {
				break
			}
			sleepNVD(c.APIKey)
		}

		windowStart = windowEnd
		if windowStart.Before(end) {
			sleepNVD(c.APIKey)
		}
	}
	return out, raws, nil
}

func sleepNVD(apiKey string) {
	if apiKey == "" {
		time.Sleep(nvdMinInterval)
	} else {
		time.Sleep(1 * time.Second)
	}
}

func (c *NVDClient) fetchPage(pubStart, pubEnd time.Time, startIndex int) (*nvdResponse, error) {
	q := url.Values{}
	q.Set("keywordSearch", c.Keyword)
	q.Set("resultsPerPage", fmt.Sprintf("%d", nvdPageSize))
	q.Set("startIndex", fmt.Sprintf("%d", startIndex))
	// NVD requires iso8601 with milliseconds
	q.Set("pubStartDate", pubStart.Format("2006-01-02T15:04:05.000")+"Z")
	q.Set("pubEndDate", pubEnd.Format("2006-01-02T15:04:05.000")+"Z")

	rawURL := c.APIBase + "?" + q.Encode()
	var lastErr error
	for attempt := 1; attempt <= maxNVDAttempts; attempt++ {
		body, err := c.getOnce(rawURL)
		if err != nil {
			lastErr = err
			backoff := time.Duration(attempt) * 3 * time.Second
			log.Printf("nvd retry %d/%d after %s: %v", attempt, maxNVDAttempts, backoff, err)
			time.Sleep(backoff)
			continue
		}
		defer body.Close()
		data, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		var page nvdResponse
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("decode nvd json: %w", err)
		}
		return &page, nil
	}
	return nil, fmt.Errorf("nvd fetch failed after %d attempts: %w", maxNVDAttempts, lastErr)
}

func (c *NVDClient) getOnce(rawURL string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUA)
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("nvd status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("nvd status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.Body, nil
}

func normalizeNVD(item nvdCVE, fetchedAt time.Time) (model.CVE, string, bool) {
	id := strings.ToUpper(strings.TrimSpace(item.ID))
	if id == "" {
		return model.CVE{}, "", false
	}
	components := componentsFromNVD(item)
	if !isOpenStackRelated(item, components) {
		return model.CVE{}, "", false
	}

	summary := ""
	for _, d := range item.Descriptions {
		if strings.EqualFold(d.Lang, "en") && strings.TrimSpace(d.Value) != "" {
			summary = strings.TrimSpace(d.Value)
			break
		}
	}
	if summary == "" && len(item.Descriptions) > 0 {
		summary = strings.TrimSpace(item.Descriptions[0].Value)
	}

	severity := ""
	switch {
	case len(item.Metrics.CVSSMetricV31) > 0:
		severity = item.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
	case len(item.Metrics.CVSSMetricV30) > 0:
		severity = item.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
	case len(item.Metrics.CVSSMetricV2) > 0:
		severity = item.Metrics.CVSSMetricV2[0].BaseSeverity
	}

	var refs []string
	for _, r := range item.References {
		if u := strings.TrimSpace(r.URL); u != "" {
			refs = append(refs, u)
		}
	}
	refs = append(refs, "https://nvd.nist.gov/vuln/detail/"+id)

	var published *time.Time
	if t, err := time.Parse(time.RFC3339, item.Published); err == nil {
		u := t.UTC()
		published = &u
	} else if t, err := time.Parse("2006-01-02T15:04:05.000", strings.TrimSuffix(item.Published, "Z")); err == nil {
		u := t.UTC()
		published = &u
	}

	rawBytes, _ := json.Marshal(item)
	cve := model.CVE{
		CVEID:       id,
		Title:       id + ": OpenStack related vulnerability",
		Summary:     summary,
		Components:  components,
		Severity:    strings.ToLower(strings.TrimSpace(severity)),
		PublishedAt: published,
		Refs:        refs,
		Source:      "nvd",
		FetchedAt:   fetchedAt,
	}
	if len(components) > 0 {
		cve.Title = id + ": " + strings.Join(components, ", ")
	}
	return cve, string(rawBytes), true
}

func isOpenStackRelated(item nvdCVE, components []string) bool {
	if len(components) > 0 {
		return true
	}
	blob := strings.ToLower(item.ID)
	for _, d := range item.Descriptions {
		blob += " " + strings.ToLower(d.Value)
	}
	return strings.Contains(blob, "openstack")
}

func componentsFromNVD(item nvdCVE) []string {
	seen := map[string]struct{}{}
	var out []string
	var walk func(nodes []nvdNode)
	walk = func(nodes []nvdNode) {
		for _, n := range nodes {
			for _, m := range n.CPEMatch {
				if name := productFromCPE(m.Criteria); name != "" {
					key := strings.ToLower(name)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, name)
				}
			}
			if len(n.Children) > 0 {
				walk(n.Children)
			}
		}
	}
	for _, cfg := range item.Configurations {
		walk(cfg.Nodes)
	}
	return out
}

// productFromCPE extracts openstack product from cpe:2.3:a:openstack:nova:...
func productFromCPE(criteria string) string {
	parts := strings.Split(criteria, ":")
	// cpe:2.3:part:vendor:product:...
	if len(parts) < 5 {
		return ""
	}
	vendor := parts[3]
	product := parts[4]
	if !strings.EqualFold(vendor, "openstack") {
		return ""
	}
	if product == "" || product == "*" {
		return "OpenStack"
	}
	// title-case-ish keep original product token
	return product
}
