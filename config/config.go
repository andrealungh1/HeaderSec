package config

import (
	"flag"
	"time"
)

type App struct {
	Targets        []string
	Method         string
	Cookie         string
	UserAgent      string
	ExtraHeaders   map[string]string
	PortOverride   int
	Timeout        time.Duration
	FollowRedirect bool
	MaxRedirects   int
	Workers        int

	IncludeRec, IncludeLeak, IncludeDepr bool

	OutputJSON    string
	Insecure      bool
	Proxy         string
	NoBanner      bool
	NoColor       bool
	NoRaccomanded bool
}

func Parse() (*App, error) {
	var (
		urlStr    = flag.String("url", "", "URL to check")
		urlFile   = flag.String("url-file", "", "Text file with one URL per line")
		method    = flag.String("method", "HEAD", "HTTP method")
		cookie    = flag.String("cookie", "", "Cookie in the format k=v")
		userAgent = flag.String("user-agent", "", "Custom User-Agent string")
		H         = flag.String("H", "", "Extra headers, format: 'K: V;K2: V2'")
		port      = flag.Int("port", 0, "Override port")
		timeout   = flag.Int("timeout", 10, "Request timeout in seconds")
		follow    = flag.Bool("follow-redirects", true, "Follow HTTP redirects")
		maxRed    = flag.Int("max-redirects", 10, "Maximum number of redirects to follow")
		workers   = flag.Int("concurrency", 20, "Number of concurrent workers")
		recFlag   = flag.Bool("rec", false, "Include only recommended headers check")
		leakFlag  = flag.Bool("leak", false, "Include only info-leaking headers check")
		depFlag   = flag.Bool("depr", false, "Include only deprecated headers check")
		jsonOut   = flag.String("json", "", "Output JSON file ('-' for stdout)")
		insecure  = flag.Bool("insecure", false, "Skip TLS certificate verification")
		proxyURL  = flag.String("proxy", "", "Proxy URL, e.g. http://127.0.0.1:8080")
		noBanner  = flag.Bool("no-banner", false, "Don't print banner")
		noColor   = flag.Bool("no-color", false, "Disable ANSI colours in output")
		noRec     = flag.Bool("no-raccomanded", false, "Show only MISSING or PRESENT for recommended headers")
	)

	flag.Parse()

	if !*recFlag && !*leakFlag && !*depFlag {
		*recFlag, *leakFlag, *depFlag = true, true, true
	}

	targets, err := collectTargets(*urlStr, *urlFile)
	if err != nil {
		return nil, err
	}

	targets = DedupeURLs(targets)

	return &App{
		Targets:        targets,
		Method:         *method,
		Cookie:         *cookie,
		UserAgent:      *userAgent,
		ExtraHeaders:   parseExtra(*H),
		PortOverride:   *port,
		Timeout:        time.Duration(*timeout) * time.Second,
		FollowRedirect: *follow,
		MaxRedirects:   *maxRed,
		Workers:        *workers,

		IncludeRec:  *recFlag,
		IncludeLeak: *leakFlag,
		IncludeDepr: *depFlag,

		OutputJSON:    *jsonOut,
		Insecure:      *insecure,
		Proxy:         *proxyURL,
		NoBanner:      *noBanner,
		NoColor:       *noColor,
		NoRaccomanded: *noRec,
	}, nil
}
