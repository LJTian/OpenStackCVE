package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is loaded from config.yaml.
type Config struct {
	SQLite SQLiteConfig `yaml:"sqlite"`
	Fetch  FetchConfig  `yaml:"fetch"`
}

type SQLiteConfig struct {
	Path string `yaml:"path"`
}

type FetchConfig struct {
	LookbackDays int        `yaml:"lookback_days"`
	Sources      []string   `yaml:"sources"`
	Source       string     `yaml:"source"` // legacy single source
	BaseURL      string     `yaml:"base_url"`
	ListURL      string     `yaml:"list_url"`
	NVD          NVDConfig  `yaml:"nvd"`
}

type NVDConfig struct {
	APIBase string `yaml:"api_base"`
	APIKey  string `yaml:"api_key"`
	Keyword string `yaml:"keyword"`
}

// Default returns sensible defaults.
func Default() Config {
	return Config{
		SQLite: SQLiteConfig{Path: "data/cve.db"},
		Fetch: FetchConfig{
			LookbackDays: 1825,
			Sources:      []string{"ossa", "nvd"},
			BaseURL:      "https://security.openstack.org/ossa",
			ListURL:      "https://security.openstack.org/ossalist.html",
			NVD: NVDConfig{
				APIBase: "https://services.nvd.nist.gov/rest/json/cves/2.0",
				Keyword: "OpenStack",
			},
		},
	}
}

// Load reads YAML from path and merges with defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.SQLite.Path == "" {
		cfg.SQLite.Path = "data/cve.db"
	}
	if cfg.Fetch.LookbackDays <= 0 {
		cfg.Fetch.LookbackDays = 1825
	}
	if len(cfg.Fetch.Sources) == 0 {
		if cfg.Fetch.Source != "" {
			cfg.Fetch.Sources = []string{cfg.Fetch.Source}
		} else {
			cfg.Fetch.Sources = []string{"ossa", "nvd"}
		}
	}
	if cfg.Fetch.BaseURL == "" {
		cfg.Fetch.BaseURL = "https://security.openstack.org/ossa"
	}
	if cfg.Fetch.ListURL == "" {
		cfg.Fetch.ListURL = "https://security.openstack.org/ossalist.html"
	}
	if cfg.Fetch.NVD.APIBase == "" {
		cfg.Fetch.NVD.APIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	if cfg.Fetch.NVD.Keyword == "" {
		cfg.Fetch.NVD.Keyword = "OpenStack"
	}
	if cfg.Fetch.NVD.APIKey == "" {
		cfg.Fetch.NVD.APIKey = os.Getenv("NVD_API_KEY")
	}
	return cfg, nil
}

// ActiveSources returns lowercased unique source names.
func (c Config) ActiveSources() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range c.Fetch.Sources {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// DSN builds a modernc.org/sqlite compatible file DSN.
func (c Config) DSN() string {
	return fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", c.SQLite.Path)
}
