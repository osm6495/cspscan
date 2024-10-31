package cmd

import (
	"fmt"
	"net/http"
	URL "net/url"
	"os"
	"strings"

	"github.com/osm6495/cspscan/internal"
	"github.com/spf13/cobra"
)

type Flags struct {
	Url string
	Threads int
  verbose bool
}

var (
	flags Flags
	rootCmd = &cobra.Command{
		Use:     "cspscan [options] <-u targetUrl | targetUrlList>",
		Short:   `A CLI toolkit to find dangling cloud storage buckets in CSP directives.`,
		Long: `A CLI toolkit to find dangling cloud storage buckets in Content Security Policy directives.`,
		Run: func(cmd *cobra.Command, args []string) {
			Scan(flags, args)
		},
	}
)

func init() {
	rootCmd.Flags().StringVarP(&flags.Url, "url", "u", "", "specify a single URL, rather than a filepath to a list of URLs")
	rootCmd.Flags().IntVarP(&flags.Threads, "threads", "t", 0, `limit the number of threads, which will 
make one HEAD request to each input url, and one GET request to each url in the CSP for each input URL.
A value of 0 will not limit the thread count.`)
  rootCmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "output all scanned URLs, even if not vulnerable")
}

func parseInputFile(filepath string) ([]string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// Probably not necessary, but prevents command injection/privilege escalation in the 
	// oddly specific scenario where this program is somwhow running with more permissions
	// than the user and the user has access to modify the url input file. 
	// Still need to avoid exposing contents of the file, to avoid unprivileged reads.
	for _, char := range string(data) {
		if char == '&' || char == ';' || char == '\''{
			return nil, fmt.Errorf("invalid character (& or ; or ') found in url file")
		}
	}

	contents := strings.Split(string(data), "\n")
	if len(contents) == 0 {
		return nil, fmt.Errorf("failed to read file: No contents found")
	}

  for i, url := range contents {
    // Remove wildcard port (":*") if present
    url = strings.Replace(url, ":*", "", 1)

    // Add "http://" if no protocol to make it a valid URL
    if !strings.Contains(url, "://") {
      url = "https://" + url
    }

    // Parse the URL and clean up any wildcard ports (like ":*")
    parsedURL, err := URL.Parse(url)
    if err != nil || parsedURL.Host == "" {
      continue
    }

    if !strings.Contains(parsedURL.Host, ".") {
      continue // Skip if no TLD
    }
    
    // Ignore wildcard subdomains
    parsedURL.Host = strings.Replace(parsedURL.Host, "*.", "", 1)

    contents[i] = parsedURL.String()
  }

	return contents, nil
}

func Scan(flags Flags, args []string) {
	var input []string
	if flags.Url != "" {
		input = append(input, flags.Url)
	} else {
		if len(args) > 0 {
			filepath := args[0]

			var err error
			input, err = parseInputFile(filepath)

			if err != nil {
				panic(fmt.Errorf("failed to parse input file: %v", err))
			}
		} else {
			panic(fmt.Errorf("missing URL or filepath"))
		}
	}

	maxThreads := len(input)
	if (flags.Threads == 0) {
		maxThreads = flags.Threads
	}

	client := http.DefaultClient

	fingerprints, err := internal.GetFingerprints("", client)
	if err != nil {
		panic(err)
	}

	urlsChannel := make(chan internal.Result)
	resultChannel := make(chan internal.Result)

	go internal.ProcessPrimaryURLs(input, urlsChannel, maxThreads, client)
	go internal.ProcessSecondaryURLs(urlsChannel, resultChannel, maxThreads, client, fingerprints)
  
	for result := range resultChannel {
		internal.ToConsole(result, flags.verbose)
	}
}

func Execute() error {
	return rootCmd.Execute()
}