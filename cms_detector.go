package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/joshuavanderpoll/CMS-Detector/fingerprints"
)

const (
	GREEN    = "\033[92m"
	BLUE     = "\033[94m"
	PURPLE   = "\033[95m"
	CYAN     = "\033[96m"
	DARKCYAN = "\033[36m"
	YELLOW   = "\033[93m"
	RED      = "\033[91m"
	BOLD     = "\033[1m"
	END      = "\033[0m"
)

type Fingerprint struct {
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
	Key    string `json:"key,omitempty"`
	Length int    `json:"length,omitempty"`
}

type CMS struct {
	Name         string        `json:"name"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

type preparedFP struct {
	fp    Fingerprint
	re    *regexp.Regexp // compiled when type == "regex"
	rawRe string
}

type preparedCMS struct {
	Name string
	FPs  []preparedFP
}

type matchResult struct {
	Name      string   `json:"name"`
	MatchedBy []string `json:"matched_by"`
}

type jsonOut struct {
	Host       string        `json:"host"`
	StatusCode int           `json:"status_code"`
	Detected   bool          `json:"detected"`
	Matches    []matchResult `json:"matches"`
	TimingMS   int64         `json:"timing_ms"`
	Redirects  int           `json:"redirects"`
	Error      string        `json:"error,omitempty"`
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return h
	}
	if !(strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://")) {
		h = "http://" + h
	}
	return strings.TrimRight(h, "/")
}

func readFingerprints() ([]CMS, error) {
	var arr []CMS
	dec := json.NewDecoder(strings.NewReader(string(fingerprints.Data)))
	if err := dec.Decode(&arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func prepare(cms []CMS) []preparedCMS {
	out := make([]preparedCMS, 0, len(cms))
	for _, c := range cms {
		pc := preparedCMS{Name: c.Name}
		for _, fp := range c.Fingerprints {
			if fp.Type == "regex" {
				pat := "(?is)" + fp.Value
				re, err := regexp.Compile(pat)
				if err != nil {
					// skip invalid regex but continue
					continue
				}
				pc.FPs = append(pc.FPs, preparedFP{fp: fp, re: re, rawRe: fp.Value})
			} else {
				pc.FPs = append(pc.FPs, preparedFP{fp: fp})
			}
		}
		out = append(out, pc)
	}
	return out
}

func headerHasKey(h http.Header, key string) bool {
	return h.Get(key) != ""
}

func headerEquals(h http.Header, key, val string) bool {
	return strings.EqualFold(h.Get(key), val)
}

func headerContains(h http.Header, key, sub string) bool {
	return strings.Contains(strings.ToLower(h.Get(key)), strings.ToLower(sub))
}

func cookiesByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func cookieExists(cookies []*http.Cookie, name string) bool {
	return cookiesByName(cookies, name) != nil
}

func cookieEquals(cookies []*http.Cookie, name, val string) bool {
	c := cookiesByName(cookies, name)
	if c == nil {
		return false
	}
	return strings.EqualFold(c.Value, val)
}

func cookieContains(cookies []*http.Cookie, name, sub string) bool {
	c := cookiesByName(cookies, name)
	if c == nil {
		return false
	}
	return strings.Contains(strings.ToLower(c.Value), strings.ToLower(sub))
}

func decodeBase64Any(s string) ([]byte, error) {
	u, _ := url.QueryUnescape(s)

	// try StdEncoding with padding fix
	normalize := func(x string) string {
		if m := len(x) % 4; m != 0 {
			x += strings.Repeat("=", 4-m)
		}
		return x
	}
	if b, err := base64.StdEncoding.DecodeString(normalize(u)); err == nil {
		return b, nil
	}
	// try URL encoding
	if b, err := base64.URLEncoding.DecodeString(normalize(u)); err == nil {
		return b, nil
	}
	// raw std
	if b, err := base64.RawStdEncoding.DecodeString(u); err == nil {
		return b, nil
	}
	// raw url
	if b, err := base64.RawURLEncoding.DecodeString(u); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("base64 decode failed")
}

func match(prepared []preparedCMS, resp *http.Response, bodyLower string) []matchResult {
	results := []matchResult{}
	h := resp.Header
	cookies := resp.Cookies()

	for _, c := range prepared {
		var matchedBy []string
		for _, pf := range c.FPs {
			fp := pf.fp
			switch fp.Type {

			case "regex":
				if pf.re != nil && pf.re.FindStringIndex(bodyLower) != nil {
					matchedBy = append(matchedBy, "regex:"+pf.rawRe)
				}

			case "string_contains":
				val := strings.ToLower(fp.Value)
				if val != "" && strings.Contains(bodyLower, val) {
					matchedBy = append(matchedBy, "string_contains:"+fp.Value)
				}

			case "strings_contain":
				parts := strings.Split(strings.ToLower(fp.Value), "|")
				all := true
				for _, p := range parts {
					if !strings.Contains(bodyLower, p) {
						all = false
						break
					}
				}
				if len(parts) > 0 && all {
					matchedBy = append(matchedBy, "strings_contain:"+fp.Value)
				}

			case "header_key_equals":
				key := fp.Value
				if key != "" && headerHasKey(h, key) {
					matchedBy = append(matchedBy, "header_key_equals:"+key)
				}

			case "header_key_value":
				key := fp.Key
				val := fp.Value
				if key != "" && headerEquals(h, key, val) {
					matchedBy = append(matchedBy, fmt.Sprintf("header_key_value:%s=%s", key, val))
				}

			case "header_key_value_contains":
				key := fp.Key
				val := fp.Value
				if key != "" && headerContains(h, key, val) {
					matchedBy = append(matchedBy, fmt.Sprintf("header_key_value_contains:%s~%s", key, val))
				}

			case "cookie_key_equals":
				name := fp.Value
				if name != "" && cookieExists(cookies, name) {
					matchedBy = append(matchedBy, "cookie_key_equals:"+name)
				}

			case "cookie_key_value":
				name := fp.Key
				val := strings.ToLower(fp.Value)
				if name != "" && cookieEquals(cookies, name, val) { // case-insensitive equality
					matchedBy = append(matchedBy, fmt.Sprintf("cookie_key_value:%s=%s", name, fp.Value))
				} else {
					// equality with case-sensitive value (fallback)
					c := cookiesByName(cookies, name)
					if c != nil && c.Value == fp.Value {
						matchedBy = append(matchedBy, fmt.Sprintf("cookie_key_value:%s=%s", name, fp.Value))
					}
				}

			case "cookie_key_value_contains":
				name := fp.Key
				val := fp.Value
				if name != "" && cookieContains(cookies, name, val) {
					matchedBy = append(matchedBy, fmt.Sprintf("cookie_key_value_contains:%s~%s", name, val))
				}

			case "cookie_key_value_b64_json_keys":
				name := fp.Key
				if c := cookiesByName(cookies, name); c != nil {
					if b, err := decodeBase64Any(c.Value); err == nil {
						var obj map[string]any
						if json.Unmarshal(b, &obj) == nil {
							req := strings.Split(strings.ToLower(fp.Value), "|")
							have := map[string]bool{}
							for k := range obj {
								have[strings.ToLower(k)] = true
							}
							ok := true
							for _, k := range req {
								if !have[k] {
									ok = false
									break
								}
							}
							if ok {
								matchedBy = append(matchedBy, fmt.Sprintf("cookie_key_value_b64_json_keys:%s has %s", name, fp.Value))
							}
						}
					}
				}

			case "cookie_substr_key_value_b64_type":
				l := fp.Length
				keySuffix := fp.Key
				expect := fp.Value
				for _, c := range cookies {
					name := c.Name
					idx := len(name) + l // l can be negative
					if idx < 0 {
						idx = 0
					}
					if idx > len(name) {
						idx = len(name)
					}
					suffix := name[idx:]
					if suffix == keySuffix {
						if b, err := decodeBase64Any(c.Value); err == nil {
							switch strings.ToLower(expect) {
							case "bytes":
								// any successful decode counts
								matchedBy = append(matchedBy, fmt.Sprintf("cookie_substr_key_value_b64_type:*%s -> %s", keySuffix, expect))
							case "string", "str":
								if utf8.Valid(b) {
									matchedBy = append(matchedBy, fmt.Sprintf("cookie_substr_key_value_b64_type:*%s -> %s", keySuffix, expect))
								}
							}
							break
						}
					}
				}

			default:
				// ignore unknown type
			}
		}
		if len(matchedBy) > 0 {
			results = append(results, matchResult{Name: c.Name, MatchedBy: matchedBy})
		}
	}
	return results
}

func main() {
	var (
		host     string
		raw      bool
		jsonMode bool
		timeout  int
		insecure bool
		ua       string
	)
	flag.StringVar(&host, "host", "", "Host or URL to scan (e.g., example.com or https://example.com)")
	flag.BoolVar(&raw, "raw", false, "Print only result name(s) in lowercase with underscores; print 'null' on no match.")
	flag.BoolVar(&jsonMode, "json", false, "Output a structured JSON result.")
	flag.IntVar(&timeout, "timeout", 10, "HTTP timeout in seconds (default: 10).")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS verification (verify=false).")
	flag.StringVar(&ua, "ua", "", "Custom User-Agent string.")
	flag.Parse()

	if host == "" && !(jsonMode || raw) {
		fmt.Print(PURPLE + "[?] Enter host to scan : " + END)
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		host = strings.TrimSpace(line)
	}
	if host == "" {
		if jsonMode {
			j := jsonOut{Error: "Missing --host"}
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(j)
		} else {
			fmt.Println(RED + "[!] Missing --host" + END)
		}
		os.Exit(1)
	}

	host = normalizeHost(host)

	// Load fingerprints
	rawFP, err := readFingerprints()
	if err != nil {
		if jsonMode {
			j := jsonOut{Host: host, Error: fmt.Sprintf("Could not parse fingerprints: %v", err)}
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(j)
		} else {
			fmt.Println(RED + fmt.Sprintf("[!] Could not parse fingerprints: %v", err) + END)
		}
		os.Exit(1)
	}
	prepared := prepare(rawFP)

	if !(raw || jsonMode) {
		fmt.Println(PURPLE + BOLD + "CMS Detector" + END)
		fmt.Println(PURPLE + "[•] Made by: https://github.com/joshuavanderpoll/CMS-Detector" + END)
		fmt.Printf(BLUE+"[@] Scanning host "+DARKCYAN+"\"%s\""+BLUE+"..."+END+"\n", host)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
	}
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}
	// track redirects
	redirects := 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirects = len(via)
		return nil
	}

	req, err := http.NewRequest("GET", host, nil)
	if err != nil {
		printErrAndExit(host, err, jsonMode)
	}
	if ua == "" {
		ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("sec-ch-ua", "\"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\", \"Not;A=Brand\";v=\"99\"")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", "\"macOS\"")
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-site", "none")
	req.Header.Set("upgrade-insecure-requests", "1")
	req.Header.Set("referer", host)

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		printErrAndExit(host, err, jsonMode)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	// match on lowercased, ' -> " replaced, trimmed
	bodyLower := strings.ToLower(strings.ReplaceAll(string(b), "'", "\""))
	bodyLower = strings.TrimSpace(bodyLower)

	matches := match(prepared, resp, bodyLower)
	detected := len(matches) > 0

	if jsonMode {
		out := jsonOut{
			Host:       host,
			StatusCode: resp.StatusCode,
			Detected:   detected,
			Matches:    matches,
			TimingMS:   elapsed.Milliseconds(),
			Redirects:  redirects,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
	} else if raw {
		if detected {
			for _, m := range matches {
				fmt.Println(GREEN + strings.ReplaceAll(strings.ToLower(strings.ReplaceAll(m.Name, " ", "_")), "’", "'") + END)
			}
		} else {
			fmt.Println("null")
		}
	} else {
		if detected {
			names := make([]string, 0, len(matches))
			for _, m := range matches {
				names = append(names, fmt.Sprintf("\"%s\"", m.Name))
			}
			fmt.Printf(GREEN+"[√] \"%s\" is using "+BLUE+"%s"+GREEN+"!"+END+"\n", host, strings.Join(names, ", "))
			for _, m := range matches {
				reasons := m.MatchedBy
				if len(reasons) > 3 {
					reasons = append(reasons[:3], fmt.Sprintf("(+%d more)", len(m.MatchedBy)-3))
				}
				fmt.Println(CYAN + "    ↳ matched by: " + strings.Join(reasons, "; ") + END)
			}
		} else {
			fmt.Println(YELLOW + "[!] No CMS could be detected." + END)
		}
	}
	if detected {
		os.Exit(0)
	}
	os.Exit(2)
}

func printErrAndExit(host string, err error, jsonMode bool) {
	if jsonMode {
		j := jsonOut{Host: host, Error: err.Error()}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(j)
	} else {
		fmt.Println(RED + fmt.Sprintf("[!] Could not retrieve host. Error: %v", err) + END)
	}
	os.Exit(1)
}
