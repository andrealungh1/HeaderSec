// scanner/scanner.go
package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andrealungh1/HeaderSec/output"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Config struct {
	Method                               string
	Cookie, UserAgent                    string
	ExtraHeaders                         map[string]string
	PortOverride                         int
	IncludeRec, IncludeLeak, IncludeDepr bool
	OutputJSON                           string
}

func Run(client *http.Client, cfg Config, targets []string, workers int) {

	if cfg.OutputJSON != "" {
		var (
			mu      sync.Mutex
			results []json.RawMessage
			wg      sync.WaitGroup
			sem     = make(chan struct{}, workers)
		)

		for _, raw := range targets {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				parsed, err := url.Parse(u)
				if err != nil {
					output.LogError("Invalid URL (%q): %v", u, err)
					return
				}
				if cfg.PortOverride > 0 {
					parsed.Host = fmt.Sprintf("%s:%d", parsed.Hostname(), cfg.PortOverride)
				}

				req, _ := http.NewRequest(cfg.Method, parsed.String(), nil)
				if cfg.Cookie != "" {
					req.Header.Set("Cookie", cfg.Cookie)
				}
				if cfg.UserAgent != "" {
					req.Header.Set("User-Agent", cfg.UserAgent)
				}
				for k, v := range cfg.ExtraHeaders {
					req.Header.Set(k, v)
				}

				resp, err := client.Do(req)
				if err != nil {
					output.LogError("Request failed: (%s): %v", parsed, err)
					return
				}
				// fallback GET se HEAD non restituisce header
				if len(resp.Header) == 0 {
					req.Method = http.MethodGet
					resp.Body.Close()
					resp, err = client.Do(req)
					if err != nil {
						output.LogError("GET request failed: (%s): %v", parsed, err)
						return
					}
				}

				data := output.ProduceJSON(parsed.String(), resp, cfg.IncludeRec, cfg.IncludeLeak, cfg.IncludeDepr)
				resp.Body.Close()

				mu.Lock()
				results = append(results, data)
				mu.Unlock()
			}(raw)
		}
		wg.Wait()

		// serializziamo l’array
		all, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			output.LogError("Failed to serialize data to JSON: %v", err)
			return
		}

		// scriviamo su file o stdout
		if cfg.OutputJSON == "-" {
			fmt.Println(string(all))
		} else {
			if err := os.WriteFile(cfg.OutputJSON, all, 0o644); err != nil {
				output.LogError("Error writing to file: %s: %v", cfg.OutputJSON, err)
			}
		}
		return
	}

	// Altrimenti modalità CLI/color originale
	if len(targets) == 1 || workers <= 1 {
		for i, t := range targets {
			scan(i, t, client, cfg)
		}
	} else {
		var wg sync.WaitGroup
		sem := make(chan struct{}, workers)
		for i, t := range targets {
			wg.Add(1)
			go func(i int, t string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				scan(i, t, client, cfg)
			}(i, t)
		}
		wg.Wait()
	}
}

// scan – singolo URL; nessun print colorato qui dentro.
func scan(idx int, raw string, client *http.Client, cfg Config) {
	parsed, err := url.Parse(raw)
	if err != nil {
		output.LogError("Invalid URL (%q): %v", raw, err)
		return
	}
	if cfg.PortOverride > 0 {
		parsed.Host = fmt.Sprintf("%s:%d", parsed.Hostname(), cfg.PortOverride)
	}

	req, err := http.NewRequest(cfg.Method, parsed.String(), nil)
	if err != nil {
		output.LogError("Error creating request: %v", err)
		return
	}
	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}
	if cfg.UserAgent != "" {
		req.Header.Set("User-Agent", cfg.UserAgent)
	}
	for k, v := range cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		output.LogError("Request failed: (%s): %v", parsed, err)
		return
	}
	if len(resp.Header) == 0 {
		req.Method = http.MethodGet
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		resp, err = client.Do(req)
		if err != nil {
			output.LogError("GET request failed: (%s): %v", parsed, err)
			return
		}
	}

	if cfg.OutputJSON != "" {
		saveJSON(idx, parsed.String(), resp, cfg)
	} else {
		output.ProduceCLI(parsed.String(), resp, cfg.IncludeRec, cfg.IncludeLeak, cfg.IncludeDepr)
	}

	if resp.Body != nil && !errors.Is(resp.Body.Close(), http.ErrBodyReadAfterClose) {
		_ = resp.Body.Close()
	}
}

func saveJSON(idx int, rawURL string, resp *http.Response, cfg Config) {
	data := output.ProduceJSON(rawURL, resp, cfg.IncludeRec, cfg.IncludeLeak, cfg.IncludeDepr)
	if cfg.OutputJSON == "-" {
		fmt.Println(string(data))
		return
	}
	path := cfg.OutputJSON
	if idx > 0 {
		ext := filepath.Ext(path)
		base := strings.TrimSuffix(path, ext)
		path = fmt.Sprintf("%s_%d%s", base, idx+1, ext)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		output.LogError("Failed to save JSON file: (%s): %v", path, err)
	}
}
