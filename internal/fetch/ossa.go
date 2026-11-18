package fetch

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"OpenStackCVE/internal/model"
)

const defaultUA = "OpenStackCVE-Cache/1.0 (+https://security.openstack.org)"

var (
	ossaIDRe   = regexp.MustCompile(`(?i)OSSA-\d{4}-\d+`)
	cveIDRe    = regexp.MustCompile(`CVE-\d{4}-\d+`)
	headerlink = "¶"
)

// OSSAClient fetches and parses OpenStack Security Advisories.
type OSSAClient struct {
	HTTP    *http.Client
	BaseURL string
	ListURL string
}

// NewOSSA returns a client with defaults.
func NewOSSA(baseURL, listURL string) *OSSAClient {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &OSSAClient{
		HTTP: &http.Client{
			Timeout:   120 * time.Second,
			Transport: transport,
		},
		BaseURL: strings.TrimRight(baseURL, "/"),
		ListURL: listURL,
	}
}

// ListIDs returns OSSA IDs from the advisory list page.
func (c *OSSAClient) ListIDs() ([]string, error) {
	body, err := c.get(c.ListURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var ids []string
	doc.Find("a[href]").Each(func(_ int, a *goquery.Selection) {
		href, _ := a.Attr("href")
		m := ossaIDRe.FindString(href)
		if m == "" {
			m = ossaIDRe.FindString(a.Text())
		}
		if m == "" {
			return
		}
		id := strings.ToUpper(m)
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	})
	return ids, nil
}

// FetchByID scrapes one advisory page.
func (c *OSSAClient) FetchByID(id string) (*model.Advisory, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	url := fmt.Sprintf("%s/%s.html", c.BaseURL, id)
	return c.FetchURL(url)
}

// FetchURL scrapes an absolute advisory URL.
func (c *OSSAClient) FetchURL(rawURL string) (*model.Advisory, error) {
	body, err := c.get(rawURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return nil, err
	}
	return parseDocument(doc, rawURL)
}

const maxHTTPAttempts = 5

func (c *OSSAClient) get(rawURL string) (io.ReadCloser, error) {
	var lastErr error
	for attempt := 1; attempt <= maxHTTPAttempts; attempt++ {
		body, err := c.getOnce(rawURL)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if attempt < maxHTTPAttempts {
			backoff := time.Duration(attempt) * 2 * time.Second
			log.Printf("retry %d/%d %s after %s: %v", attempt, maxHTTPAttempts, rawURL, backoff, err)
			time.Sleep(backoff)
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxHTTPAttempts, lastErr)
}

func (c *OSSAClient) getOnce(rawURL string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUA)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("fetch %s: status %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.Body, nil
}

func parseDocument(doc *goquery.Document, sourceURL string) (*model.Advisory, error) {
	main := doc.Find(`[role="main"]`).First()
	if main.Length() == 0 {
		main = doc.Find(".docs-body").First()
	}
	if main.Length() == 0 {
		return nil, fmt.Errorf("advisory content not found")
	}

	title := cleanText(main.Find("h1").First().Text())
	if title == "" {
		return nil, fmt.Errorf("advisory title not found")
	}

	adv := &model.Advisory{
		ID:         extractOSSAID(title),
		Title:      title,
		CVEs:       []string{},
		Affects:    []string{},
		Patches:    []model.Patch{},
		Credits:    []string{},
		References: []string{},
		Notes:      []string{},
		SourceURL:  sourceURL,
		UpdatedAt:  cleanText(doc.Find(".docs-updated").First().Text()),
	}
	if adv.UpdatedAt != "" {
		adv.UpdatedAt = strings.TrimSpace(strings.TrimPrefix(adv.UpdatedAt, "this page last updated:"))
	}

	main.Find("dl.field-list").First().Find("dt").Each(func(_ int, dt *goquery.Selection) {
		label := strings.TrimSuffix(cleanText(dt.Text()), ":")
		value := cleanText(dt.NextFiltered("dd").Text())
		switch strings.ToLower(label) {
		case "date":
			adv.Date = value
		case "cve":
			adv.CVEs = cveIDRe.FindAllString(value, -1)
			if adv.CVEs == nil {
				adv.CVEs = []string{}
			}
		}
	})

	main.Find("section").Each(func(_ int, section *goquery.Selection) {
		id, _ := section.Attr("id")
		switch id {
		case "affects":
			adv.Affects = listTexts(section)
		case "description":
			var parts []string
			section.ChildrenFiltered("p").Each(func(_ int, p *goquery.Selection) {
				if t := cleanText(p.Text()); t != "" {
					parts = append(parts, t)
				}
			})
			adv.Description = strings.Join(parts, "\n\n")
		case "patches":
			adv.Patches = parsePatches(section)
		case "credits":
			adv.Credits = listTexts(section)
		case "references":
			adv.References = listHrefsOrTexts(section)
		case "notes":
			adv.Notes = listTexts(section)
		}
	})
	return adv, nil
}

func parsePatches(section *goquery.Selection) []model.Patch {
	var patches []model.Patch
	section.Find("li").Each(func(_ int, li *goquery.Selection) {
		a := li.Find("a").First()
		url, _ := a.Attr("href")
		text := cleanText(li.Text())
		if url == "" {
			if fields := strings.Fields(text); len(fields) > 0 {
				url = fields[0]
			}
		}
		if url == "" {
			return
		}
		release := ""
		if i := strings.Index(text, "("); i >= 0 {
			release = strings.TrimSpace(strings.TrimSuffix(text[i+1:], ")"))
		}
		patches = append(patches, model.Patch{URL: url, Release: release})
	})
	if patches == nil {
		return []model.Patch{}
	}
	return patches
}

func listTexts(section *goquery.Selection) []string {
	var items []string
	section.Find("li").Each(func(_ int, li *goquery.Selection) {
		if t := cleanText(li.Text()); t != "" {
			items = append(items, t)
		}
	})
	if items == nil {
		return []string{}
	}
	return items
}

func listHrefsOrTexts(section *goquery.Selection) []string {
	var items []string
	section.Find("li").Each(func(_ int, li *goquery.Selection) {
		if href, ok := li.Find("a").First().Attr("href"); ok && href != "" {
			items = append(items, href)
			return
		}
		if t := cleanText(li.Text()); t != "" {
			items = append(items, t)
		}
	})
	if items == nil {
		return []string{}
	}
	return items
}

func extractOSSAID(title string) string {
	parts := strings.SplitN(title, ":", 2)
	if len(parts) == 0 {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(parts[0]))
}

func cleanText(s string) string {
	s = strings.ReplaceAll(s, headerlink, "")
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimSpace(s)
}

// WithinLookback reports whether the advisory date is on/after the cutoff.
// Unknown/unparseable dates are kept (return true) so we do not drop recent unparsed pages.
func WithinLookback(date string, lookbackDays int, now time.Time) bool {
	if lookbackDays <= 0 {
		return true
	}
	cutoff := now.UTC().AddDate(0, 0, -lookbackDays)
	layouts := []string{"January 2, 2006", "Jan 2, 2006", "2006-01-02", time.RFC3339}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, strings.TrimSpace(date)); err == nil {
			return !t.UTC().Before(cutoff)
		}
	}
	log.Printf("warn: cannot parse date %q; keeping advisory", date)
	return true
}
