package internal

import (
	"fmt"
	"net/http"
	URL "net/url"
	"strings"
)

// Parse links out of a CSP. URLs that can't be parsed will be skipped.
func parseCSP(res *http.Response) []string {
	csp := res.Header.Get("Content-Security-Policy")
	if csp == "" {
		// Return a pointer to an empty string slice, rather than no pointer to indicate that no
		// CSP was found, but the request was successful.
		return []string{}
	}

	var urls []string
	directives := strings.Split(csp, ";")

	for _, directive := range directives {
		sources := strings.Fields(directive)
		if len(sources) < 2 {
			continue // Skip if no sources after directive name
		}

		// Loop over sources (ignore the first entry, which is the directive name)
		for _, source := range sources[1:] {
			// Ignore CSP keywords and exact wildcard subdomains
			if source == "'self'" || source == "'none'" || source == "*" {
				continue
			}

			// Remove wildcard port (":*") if present
			source = strings.Replace(source, ":*", "", 1)

			// Add "http://" if no protocol to make it a valid URL
			if !strings.Contains(source, "://") {
				source = "https://" + source
			}

			// Parse the URL and clean up any wildcard ports (like ":*")
			parsedURL, err := URL.Parse(source)
			if err != nil || parsedURL.Host == "" {
				continue
			}

			if !strings.Contains(parsedURL.Host, ".") {
				continue // Skip if no TLD
			}
			
			// Ignore wildcard domains
			if strings.HasPrefix(parsedURL.Host, "*.") {
				continue
			}

			// Add the URL to the list
			urls = append(urls, parsedURL.String())
		}
	}

	return urls
}

// Send a HEAD request and parse the links from the response.
func GetCSP(rawURL string, client *http.Client) ([]string, error) {
	url, err := URL.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	res, err := http.Head(url.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get CSP for %s: %v", url, err)
	}
	defer res.Body.Close()

	out := parseCSP(res)

	return out, nil
}