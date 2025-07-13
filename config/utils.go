package config

import (
	"bufio"
	"fmt"
	"github.com/andrealungh1/HeaderSec/output"
	"os"
	"strings"
)

const Banner = "  _   _                _           ____            \n" +
	" | | | | ___  __ _  __| | ___ _ __/ ___|  ___  ___ \n" +
	" | |_| |/ _ \\/ _` |/ _` |/ _ \\ '__\\___ \\ / _ \\/ __|\n" +
	" |  _  |  __/ (_| | (_| |  __/ |   ___) |  __/ (__ \n" +
	" |_| |_|\\___|\\__,_|\\__,_|\\___|_|  |____/ \\___|\\___|\n" +
	"                                                  \n" +
	"  	 By Andrea Lunghi v1.0.3\n"

func collectTargets(single, file string) ([]string, error) {
	var targets []string

	if single != "" {
		targets = append(targets, single)
	}

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("Opening URL file: %w", err)
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if u := strings.TrimSpace(sc.Text()); u != "" {
				targets = append(targets, u)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("Reading URL file: %w", err)
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("You must specify either -url or -url-file")
	}
	return targets, nil
}

func parseExtra(raw string) map[string]string {
	hdrs := make(map[string]string)
	if raw == "" {
		return hdrs
	}
	for _, h := range strings.Split(raw, ";") {
		if h = strings.TrimSpace(h); h == "" {
			continue
		}
		kv := strings.SplitN(h, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if key != "" {
			hdrs[key] = val
		}
	}
	return hdrs
}

func DedupeURLs(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	var out []string
	for _, u := range urls {
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

func PrintBanner() {
	fmt.Print("\n", output.Cyan, Banner, output.Reset, "\n\n")
}
