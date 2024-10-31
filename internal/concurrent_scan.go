package internal

import (
	"net/http"
	"sync"
)

type Result struct {
	PrimaryURL    string
	SecondaryURL  string
	Vulnerable   bool
	Error error
}

func (r Result) IsSameAs(other Result) bool {
	return r.PrimaryURL == other.PrimaryURL &&
		r.SecondaryURL == other.SecondaryURL &&
		r.Vulnerable == other.Vulnerable &&
		r.Error == other.Error
}


// Create threadLimit (or len(input) many threads if threadLimit is 0) to concurrently run GetCSP() from csp.go.
// Results are stored in the urlsChan channel as a Result for each secondaryUrl found in the CSP.
func ProcessPrimaryURLs(
	input []string, 
	urlsChan chan<- Result, 
	threadLimit int, 
	client *http.Client,
) {
	var wg sync.WaitGroup

	if threadLimit == 0 {
		threadLimit = len(input)
	}
	// Make a semaphore to limit the number of threads. 
	// Struct{} is used since no memory is allocated and we only care about the buffer size.
	sem := make(chan struct{}, threadLimit)

	for _, url := range input {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			// Acquire semaphore. Sends an empty struct to the channel
			// which will block this when we are at the thread limit.
			sem <- struct{}{}

			secondaryUrls, err := GetCSP(url, client)
			if err != nil {
				urlsChan <- Result{PrimaryURL: url, Error: err}
				<-sem //Release semaphore when done, even if error is found
				return
			}

			for _, secondaryUrl := range secondaryUrls {
				urlsChan <- Result{PrimaryURL: url, SecondaryURL: secondaryUrl}
			}

			<-sem //Release semaphore
		}(url)
	}

	wg.Wait()
	close(urlsChan)
}

// Create threadLimit (or 1000 threads if threadLimit is 0) to concurrently run CheckURL() from subdomain_takeover.go.
// Results are stored in the resultsChan channel.
func ProcessSecondaryURLs(
	urlsChan <-chan Result,
	resultsChan chan<- Result,
	threadLimit int,
	client *http.Client,
	fingerprints []Fingerprint,
) {
	var wg sync.WaitGroup

	if threadLimit == 0 {
		threadLimit = 1000
	}

	// Make a semaphore to limit the number of threads. 
	// Struct{} is used since no memory is allocated and we only care about the buffer size.
	sem := make(chan struct{}, threadLimit)

	for result := range urlsChan {
		if result.Error != nil {
			continue
		}

		wg.Add(1)
		go func(result Result) {
			defer wg.Done()
			// Acquire semaphore. Sends an empty struct to the channel
			// which will block this when we are at the thread limit.
			sem <- struct{}{}

			vulnerable, err := CheckURL(result.SecondaryURL, fingerprints, client)
			if err != nil {
				resultsChan <- Result{
					PrimaryURL: result.PrimaryURL, 
					SecondaryURL: result.SecondaryURL, 
					Vulnerable: false, 
					Error: err,
				}
				<-sem //Release semaphore when done, even if error is found
				return
			}

			resultsChan <- Result{
				PrimaryURL: result.PrimaryURL, 
				SecondaryURL: result.SecondaryURL, 
				Vulnerable: vulnerable,
			}

			<-sem //Release semaphore
		}(result)
	}

	wg.Wait()
	close(resultsChan)
}