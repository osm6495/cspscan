package internal

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseCSP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src https://example.com http://scripts.example.org http://*.example.org https://example.org:5443 http://test.example.org:*/path;")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resp, err := http.Head(server.URL)
	if err != nil {
		t.Errorf("Error in HEAD request: %v", err)
	}
	defer resp.Body.Close()

	expectedCSP := []string{
		"https://example.com",
		"http://scripts.example.org",
		"https://example.org:5443",
		"http://test.example.org/path",
	}

	csp := parseCSP(resp)
	if !reflect.DeepEqual(csp, expectedCSP) {
		t.Logf("Expected: %v\n", expectedCSP)
		t.Logf("Got:      %v\n", csp)
		t.Error("results did not match expected.")
	}
	
}

func TestGetCSP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src https://example.com http://scripts.example.org http://*.example.org https://example.org:5443 http://test.example.org:*/path;")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	expectedCSP := []string{
		"https://example.com",
		"http://scripts.example.org",
		"https://example.org:5443",
		"http://test.example.org/path",
	}

	client := http.DefaultClient

	csp, err := GetCSP(server.URL, client)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(csp, expectedCSP) {
		t.Logf("Expected: %v\n", expectedCSP)
		t.Logf("Got %v\n", csp)
		t.Error("results did not match expected.")
	}
	
}