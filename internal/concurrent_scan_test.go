package internal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

// Helper function to keep TestIsSameAs from being massive
func result(primary, secondary string, vuln bool, err error) Result {
	return Result{
		PrimaryURL: primary,
		SecondaryURL: secondary,
		Vulnerable: vuln,
		Error: err,
	}
}

func TestIsSameAs(t *testing.T) {
	errA := fmt.Errorf("error A")
	errB := fmt.Errorf("error B")

	tests := []struct {
		description string
		result Result
		other Result
		expected bool
	}{
		{"same result", result("url1", "url2", true, nil), result("url1", "url2", true, nil), true},
		{"nil err & actual err", result("url1", "url2", true, nil), result("url1", "url2", true, errA), false},
		{"nil err & nil err", result("url1", "url2", true, nil), result("url1", "url2", true, nil), true},
		{"same err", result("url1", "url2", true, errA), result("url1", "url2", true, errA), true},
		{"different err", result("url1", "url2", true, errA), result("url1", "url2", true, errB), false},
		{"different primary url", result("url1", "url2", true, nil), result("urlX", "url2", true, nil), false},
		{"different secondary url", result("url1", "url2", true, nil), result("url1", "urlX", true, nil), false},
		{"different vuln", result("url1", "url2", false, nil), result("url1", "urlX", true, nil), false},
	}

	for _, test := range tests {
		got := test.result.IsSameAs(test.other)
		if got != test.expected {
			t.Errorf("expected %v, got %v", test.expected, got)
		}
	}
}

func TestProcessPrimaryURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src https://example.com http://scripts.example.org;")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	expectedCSP := []string{
		"https://example.com",
		"http://scripts.example.org",
	}

	urlsChannel := make(chan Result)
	client := http.DefaultClient

	go ProcessPrimaryURLs([]string{server.URL}, urlsChannel, 0, client)

	var results []string
	for result := range urlsChannel {
		if result.Error != nil {
			t.Error(result.Error)
		}

		results = append(results, result.SecondaryURL)
	}

	if !reflect.DeepEqual(results, expectedCSP) {
		t.Logf("Expected: %v\n", expectedCSP)
		t.Logf("Got %v\n", results)
		t.Error("results did not match expected.")
	}
}

func TestProcessSecondaryURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer server.Close()

	exampleResult := Result{
		PrimaryURL: server.URL,
		SecondaryURL: server.URL,
	}

	expectedResult := Result{
		PrimaryURL: server.URL,
		SecondaryURL: server.URL,
		Vulnerable: true,
	}

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Error(err)
	}

	exampleFingerprint := Fingerprint{
		Cname: []string{parsedURL.Host},
		Fingerprint: "test",
		NXDomain: false,
		Vulnerable: true,
	}

	fingerprints := []Fingerprint{exampleFingerprint}

	urlsChannel := make(chan Result, 1)
	urlsChannel <- exampleResult
	close(urlsChannel)

	resultsChannel := make(chan Result)
	client := http.DefaultClient

	go ProcessSecondaryURLs(urlsChannel, resultsChannel, 0, client, fingerprints)

	for result := range resultsChannel {
		if result.Error != nil {
			t.Error(result.Error)
		}

		if !result.IsSameAs(expectedResult) {
			t.Logf("Expected: %v\n", expectedResult)
			t.Logf("Got %v\n", result)
			t.Error("results did not match expected.")
		}
	}
}

func TestProcessPrimaryURLsBulk(t *testing.T) {
	const URLCount = 10000

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src https://example.com http://scripts.example.org;")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	expectedCSP := map[string]int{
		"https://example.com": URLCount,
		"http://scripts.example.org": URLCount,
	}

	urlsChannel := make(chan Result)
	var results = make(map[string]int)
	client := http.DefaultClient

	inputURLs := make([]string, URLCount)
	for i := 0; i < URLCount; i++ {
		inputURLs[i] = server.URL
	}

	// Test with no thread limit
	go ProcessPrimaryURLs(inputURLs, urlsChannel, 0, client)

	for result := range urlsChannel {
		if result.Error != nil {
			t.Error(result.Error)
		}

		results[result.SecondaryURL] = results[result.SecondaryURL] + 1
	}

	if !reflect.DeepEqual(results, expectedCSP) {
		t.Logf("Expected: %v\n", expectedCSP)
		t.Logf("Got %v\n", results)
		t.Error("results did not match expected.")
	}

	// Test with thread limit (not URLCount many threads, since no limit should create up to that amount)
	urlsChannel2 := make(chan Result)
	var results2 = make(map[string]int)

	go ProcessPrimaryURLs(inputURLs, urlsChannel2, 10, client)
	
	for result := range urlsChannel2 {
		if result.Error != nil {
			t.Error(result.Error)
		}

		results2[result.SecondaryURL] = results2[result.SecondaryURL] + 1
	}

	if !reflect.DeepEqual(results2, expectedCSP) {
		t.Logf("Expected: %v\n", expectedCSP)
		t.Logf("Got %v\n", results2)
		t.Error("results did not match expected.")
	}
}