package output

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"golang.org/x/term"
)

const (
	Red    = "\x1b[31m"
	Green  = "\x1b[32m"
	Yellow = "\x1b[33m"
	Bold   = "\x1b[1m"
	Reset  = "\x1b[0m"

	tick  = "✓"
	cross = "✕"
	warn  = "!"
)

var (
	red = func(s string) string {
		return Red + s + Reset
	}
	green = func(s string) string {
		return Green + s + Reset
	}
	yellow = func(s string) string {
		return Yellow + s + Reset
	}
)

func yellowBold(s string) string {
	return Yellow + Bold + s + Reset
}

func wrap(s string, limit int) []string {
	s = strings.TrimSpace(s)
	if len(s) <= limit || limit <= 0 {
		return []string{s}
	}
	var out []string
	for len(s) > limit {
		cut := strings.LastIndex(s[:limit], " ")
		if cut <= 0 {
			cut = limit
		}
		out = append(out, strings.TrimSpace(s[:cut]))
		s = strings.TrimSpace(s[cut:])
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

var recommended = map[string]string{
	"Strict-Transport-Security":            "max-age=31536000; includeSubDomains",
	"X-Content-Type-Options":               "nosniff",
	"Content-Security-Policy":             "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
	"X-Permitted-Cross-Domain-Policies":   "none",
	"Referrer-Policy":                     "no-referrer",
	"Clear-Site-Data":                     `"cache","cookies","storage"`,
	"Cross-Origin-Embedder-Policy":        "require-corp",
	"Cross-Origin-Opener-Policy":          "same-origin",
	"Cross-Origin-Resource-Policy":        "same-origin",
	"Permissions-Policy":                  `accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()`,
	"Cache-Control":                       "no-cache, no-store, must-revalidate",
}

var leaks = []string{
	"$wsep", "Host-Header", "Server", "X-Powered-By", "X-Server-Powered-By", "X-Powered-CMS", "X-Generator", "X-Generated-By", "X-CMS", "X-Powered-By-Plesk", "X-Php-Version", "Powered-By", "X-Content-Encoded-By", "Product", "X-CF-Powered-By", "X-Framework", "Pega-Host", "X-AspNet-Version", "X-AspNetMvc-Version", "X-SourceFiles", "X-Redirect-By", "X-OWA-Version", "X-Umbraco-Version", "OracleCommerceCloud-Version", "X-BEServer", "X-DiagInfo", "X-FEServer", "X-CalculatedBETarget", "X-Cocoon-Version", "X-Jitsi-Release", "X-Joomla-Version", "X-Litespeed-Cache-Control", "X-LiteSpeed-Purge", "X-LiteSpeed-Tag", "X-LiteSpeed-Vary", "X-LiteSpeed-Cache", "X-Nextjs-Matched-Path", "X-Nextjs-Page", "X-Nextjs-Cache", "X-Nextjs-Redirect", "X-OneAgent-JS-Injection", "X-ruxit-JS-Agent", "X-dtHealthCheck", "X-dtAgentId", "X-dtInjectedServlet", "X-Kubernetes-PF-FlowSchema-UI", "X-Kubernetes-PF-PriorityLevel-UID", "X-B3-ParentSpanId", "X-B3-Sampled", "X-B3-SpanId", "X-B3-TraceId", "K-Proxy-Request", "X-Backside-Transport", "X-Varnish-Backend", "X-Varnish-Server", "X-Envoy-Upstream-Service-Time", "X-Envoy-Attempt-Count", "X-Envoy-External-Address", "X-Envoy-Internal", "X-Envoy-Original-Dst-Host", "X-Mod-Pagespeed", "X-Page-Speed", "Liferay-Portal", "SourceMap", "X-SourceMap", "X-Atmosphere-first-request", "X-Atmosphere-tracking-id", "X-Atmosphere-error",
}

var deprecated = map[string]string{
    "Expect-CT":           "N/A",
    "Public-Key-Pins":     "N/A",
    "X-XSS-Protection":    "Content-Security-Policy",
    "Pragma":              "Cache-Control",
    "Feature-Policy":      "Permissions-Policy",
}

type RecFinding struct {
	Header      string `json:"header"`
	Status      string `json:"status"`
	Observed    string `json:"observed,omitempty"`
	Recommended string `json:"recommended,omitempty"`
}

type LeakFinding struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

type result struct {
	URL         string        `json:"url"`
	Recommended []RecFinding  `json:"recommended,omitempty"`
	Leaks       []LeakFinding `json:"leaks,omitempty"`
	Deprecated  []string      `json:"deprecated,omitempty"`
}

func section(title string) {
	fmt.Fprintln(os.Stdout, yellowBold("[+] "+title))
}

func ProduceCLI(u string, resp *http.Response, doRec, doLeak, doDep bool) {
	fmt.Printf("%sAnalyzing:%s %s\n\n", Bold, Reset, u)
	arrow := "→"

	if doRec {
		section("Recommended Security Headers")
		keys := make([]string, 0, len(recommended))
		for k := range recommended {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for idx, hdr := range keys {
			want := recommended[hdr]
			val := strings.TrimSpace(resp.Header.Get(hdr))
			last := idx == len(keys)-1
			branch := "├─"
			if last {
				branch = "└─"
			}

			vert := "│"
			if last {
				vert = " "
			}

			icon := red("[" + cross + "]")
			lines := []string{}
			switch {
			case val == "":
				lines = append(lines, "MISSING")
			case strings.EqualFold(val, want):
				icon = green("[" + tick + "]")
				lines = append(lines, "OK")
			default:
				icon = yellow("[" + warn + "]")
				lines = append(lines, fmt.Sprintf("DIFF %s", val))
			}
			if val == "" || !strings.EqualFold(val, want) {
				lines = append(lines, fmt.Sprintf("Recommended: %s", want))
			}

			fmt.Printf(" %s %s %s\n", branch, icon, hdr)

			const defaultWidth = 150
			w, _, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil || w <= 0 {
				w = defaultWidth
			}
			maxWidth := w

			for _, raw := range lines {
				prefix1 := fmt.Sprintf(" %s  %s ", vert, arrow)
				prefix2 := strings.Replace(prefix1, arrow, strings.Repeat(" ", len(arrow)), 1)
				indentLen := len(prefix1)
				for i, w := range wrap(raw, maxWidth-indentLen) {
					if i == 0 {
						fmt.Printf("%s%s\n", prefix1, w)
					} else {
						fmt.Printf("%s%s\n", prefix2, w)
					}
				}
			}
			if !last {
				fmt.Println(" │")
			}
		}
		fmt.Println()
	}

	if doLeak {
		section("Information-Leak Headers")
		present := []LeakFinding{}
		for _, hdr := range leaks {
			if val := strings.TrimSpace(resp.Header.Get(hdr)); val != "" {
				present = append(present, LeakFinding{
					Header: hdr,
					Value:  val,
				})
			}
		}
		if len(present) == 0 {
			fmt.Printf(" %s %s None found\n\n", "└─", green("["+tick+"]"))
		} else {
			for idx, lf := range present {
				last := idx == len(present)-1
				branch := "├─"
				if last {
					branch = "└─"
				}
				fmt.Printf(" %s %s %s: %s\n", branch, yellow("[!]"), lf.Header, lf.Value)
				if !last {
					fmt.Println(" │")
				}
			}
			fmt.Println()
		}
	}

	if doDep {
		section("Deprecated Headers")
		present := []string{}
		for hdr := range deprecated { // for _, hdr := range deprecated {
			if resp.Header.Get(hdr) != "" {
				present = append(present, hdr)
			}
		}
		if len(present) == 0 {
			fmt.Printf(" %s %s None found\n\n", "└─", green("["+tick+"]"))
		} else {
			for idx, hdr := range present {
				last := idx == len(present)-1
				branch := "├─"
				if last {
					branch = "└─"
				}
				if rep := deprecated[hdr]; rep != "N/A" {
    					fmt.Printf(" %s %s %s (use \"%s\" instead)\n", branch, yellow("["+warn+"]"), hdr, deprecated[hdr])
				}
				if !last {
					fmt.Println(" │")
				}
			}
			fmt.Println()
		}
	}
}

func ProduceJSON(u string, resp *http.Response, doRec, doLeak, doDep bool) []byte {
	res := result{
		URL: u,
	}

	if doRec {
		for hdr, want := range recommended {
			val := strings.TrimSpace(resp.Header.Get(hdr))
			f := RecFinding{
				Header:      hdr,
				Recommended: want,
			}
			switch {
			case val == "":
				f.Status = "missing"
			case strings.EqualFold(val, want):
				f.Status = "ok"
			default:
				f.Status = "different"
				f.Observed = val
			}
			res.Recommended = append(res.Recommended, f)
		}
	}

	if doLeak {
		for _, hdr := range leaks {
			if val := strings.TrimSpace(resp.Header.Get(hdr)); val != "" {
				res.Leaks = append(res.Leaks, LeakFinding{
					Header: hdr,
					Value:  val,
				})
			}
		}
	}

	if doDep {
		for _, hdr := range deprecated {
			if resp.Header.Get(hdr) != "" {
				res.Deprecated = append(res.Deprecated, hdr)
			}
		}
	}

	data, _ := json.MarshalIndent(res, "", "  ")
	return data
}
