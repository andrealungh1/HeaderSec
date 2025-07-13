package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrealungh1/HeaderSec/config"
	"github.com/andrealungh1/HeaderSec/output"
	"github.com/andrealungh1/HeaderSec/scanner"
	"github.com/andrealungh1/HeaderSec/transport"
)

func main() {

	flag.Usage = func() {
		name := filepath.Base(os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(),
			"\nUsage: %s -url <URL> [options]\n\n", name)

		fmt.Fprintln(flag.CommandLine.Output(), "Target selection:")
		fmt.Fprintln(flag.CommandLine.Output(), "  -url string\n\tURL to check")
		fmt.Fprintln(flag.CommandLine.Output(), "  -url-file string\n\tText file with one URL per line")
		fmt.Fprintln(flag.CommandLine.Output(), "  -port int\n\tOverride port")
		fmt.Fprintln(flag.CommandLine.Output(), "  -proxy string\n\tProxy URL, e.g. http://127.0.0.1:8080")
		fmt.Fprintln(flag.CommandLine.Output(), "  -insecure\n\tSkip TLS certificate verification\n")

		fmt.Fprintln(flag.CommandLine.Output(), "Request customization:")
		fmt.Fprintln(flag.CommandLine.Output(), "  -method string\n\tHTTP method to use (default \"HEAD\")")
		fmt.Fprintln(flag.CommandLine.Output(), "  -cookie string\n\tCookie in the format k=v")
		fmt.Fprintln(flag.CommandLine.Output(), "  -user-agent string\n\tCustom User-Agent string")
		fmt.Fprintln(flag.CommandLine.Output(), "  -H string\n\tExtra headers, format: 'K: V;K2: V2'\n")

		fmt.Fprintln(flag.CommandLine.Output(), "Redirect and timeout:")
		fmt.Fprintln(flag.CommandLine.Output(), "  -follow-redirects\n\tFollow HTTP redirects (default true)")
		fmt.Fprintln(flag.CommandLine.Output(), "  -max-redirects int\n\tMaximum number of redirects to follow (default 10)")
		fmt.Fprintln(flag.CommandLine.Output(), "  -timeout int\n\tRequest timeout in seconds (default 10)\n")

		fmt.Fprintln(flag.CommandLine.Output(), "Scan behavior:")
		fmt.Fprintln(flag.CommandLine.Output(), "  -concurrency int\n\tNumber of concurrent workers (default 20)")
		fmt.Fprintln(flag.CommandLine.Output(), "  -rec\n\tInclude only recommended headers check")
		fmt.Fprintln(flag.CommandLine.Output(), "  -leak\n\tInclude only info-leaking headers check")
		fmt.Fprintln(flag.CommandLine.Output(), "  -depr\n\tInclude only deprecated headers check")
		fmt.Fprintln(flag.CommandLine.Output(), "  -no-raccomanded\n\tPrint only PRESENT or MISSING without printing the recommended values\n")

		fmt.Fprintln(flag.CommandLine.Output(), "Output:")
		fmt.Fprintln(flag.CommandLine.Output(), "  -json string\n\tOutput JSON file ('-' for stdout)")
		fmt.Fprintln(flag.CommandLine.Output(), "  -no-banner\n\tDon't print the ASCII banner at start-up")
		fmt.Fprintln(flag.CommandLine.Output(), "  -no-color\n\tDisable ANSI colours in output")
	}

	cfg, err := config.Parse()

	if flag.NFlag() == 0 {
		fmt.Println("\n\033[31mNo flags provided. Please specify at least -url\033[0m")
		return
	}

	if cfg.NoRaccomanded {
		output.ShowRecommendedDetails = false
	}

	if cfg.NoColor {
		output.DisableColors()
	}

	if !cfg.NoBanner {
		config.PrintBanner()
	}

	if err != nil {
		output.LogError("%v", err)
		os.Exit(1)
	}

	client, err := transport.New(
		cfg.Timeout,
		cfg.Insecure,
		cfg.Proxy,
		cfg.FollowRedirect,
		cfg.MaxRedirects,
	)
	if err != nil {
		output.LogError("Transport: %v", err)
		os.Exit(1)
	}

	scanner.Run(client, scanner.Config{
		Method:       cfg.Method,
		Cookie:       cfg.Cookie,
		UserAgent:    cfg.UserAgent,
		ExtraHeaders: cfg.ExtraHeaders,
		PortOverride: cfg.PortOverride,
		IncludeRec:   cfg.IncludeRec,
		IncludeLeak:  cfg.IncludeLeak,
		IncludeDepr:  cfg.IncludeDepr,
		OutputJSON:   cfg.OutputJSON,
	}, cfg.Targets, cfg.Workers)

	fmt.Println(output.Green + "Done." + output.Reset)
}
