package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	URL "net/url"
	"reflect"
	"regexp"
)

// Fingerprint imported from https://github.com/EdOverflow/can-i-take-over-xyz with regex checks for common subdomain takeover vulnerabilities.
type Fingerprint struct {
	Cname []string `json:"cname"`
	Discussion string `json:"discussion"`
	Fingerprint string `json:"fingerprint"`
	NXDomain bool `json:"nxdomain"`
	Service string `json:"service"`
	Vulnerable bool `json:"vulnerable"`
}

func (f Fingerprint) containsUrl(url URL.URL) bool {
	for _, cname := range f.Cname {
		if cname == url.Host {
			return true
		}
	}

	return false
}

func (f Fingerprint) IsSameAs(other Fingerprint) bool {
	return reflect.DeepEqual(f, other)
}

// Gets list of common subdomain takeover vulnerability detection regexes from 
// https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/refs/heads/master/fingerprints.json
//
// Parameters:
// 	- testingReplacementURL: OPTIONAL url string which will replace the URL for the fingerprints if provided, for use in testing.
//		If you don't want to overwrite the URL, you can leave this as an empty string ("") and it will default to the correct URL.
func GetFingerprints(testingReplacementURL string, client *http.Client) ([]Fingerprint, error) {
	var url string
	if testingReplacementURL != "" {
		url = testingReplacementURL
	} else {
		url = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/refs/heads/master/fingerprints.json"
	}
	
	res, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to update subdomain takeover fingerprints: %v", err)
	}
	defer res.Body.Close()
	
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to update subdomain takeover fingerprints: %v", err)
	}

	var fingerprints []Fingerprint
	err = json.Unmarshal(bytes, &fingerprints)
	if err != nil {
		return nil, fmt.Errorf("failed to update subdomain takeover fingerprints: %v", err)
	}

	// Remove non-vulnerable fingerprints from list
	for index, fingerprint := range fingerprints {
		if fingerprint.Vulnerable{
			continue
		}

		if index < len(fingerprints) - 1 {
			fingerprints = append(fingerprints[:index], fingerprints[index+1:]... )
		} else {
			fingerprints = fingerprints[:index]
		}
	}

	return fingerprints, nil
}

// Check if a URL returns an NXDOMAIN response to DNS lookups.
func checkNXDomain(url string) (bool, error) {
	_, err := net.LookupHost(url)
	if err != nil {
		dnsErr, ok := err.(*net.DNSError)
		if ok && dnsErr.IsNotFound {
			return true, nil
		}
		return false, err
	}

	return false, nil
}

// Send a GET request to the URL and check the response for the regex from the fingerprint.
// If the fingerprint matches, the URL may be vulnerable to subdomain takeover.
func checkResponse(url string, regex *regexp.Regexp, client *http.Client) (bool, error){
	res, err := client.Get(url)
	if err != nil {
		return false, fmt.Errorf("failed to GET %s: %v", url, err)
	}
	defer res.Body.Close()

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("failed to parse response: %v", err)
	}

	return regex.Match(bytes), nil


}

// Check if the provided URL may be vulnerable to subdomain takeover.
//
// Parameters:
// 	- rawURL: URL to check. Only host is read, so protocol and path are ignored.
// 	- fingerprints: Detection fingerprint regexes are passed in as a parameter so only one
// 		call to GetFingerprints() is needed.
func CheckURL(rawURL string, fingerprints []Fingerprint, client *http.Client) (bool, error) {
	url, err := URL.Parse(rawURL)
	if err != nil {
		return false, fmt.Errorf("failed to parse URL %s: %v", url, err)
	}

	for _, fingerprint := range fingerprints {
		if !fingerprint.containsUrl(*url) {
			continue
		}

		if (fingerprint.NXDomain) {
			return checkNXDomain(rawURL)
		} 

		re, err := regexp.Compile(fingerprint.Fingerprint)
		if err != nil {
			return false, fmt.Errorf("failed to compile vulnerability detection fingerprint %s:  %v", fingerprint.Fingerprint, err)
		}

		return checkResponse(rawURL, re, client)
	}

	// URL did not match any fingerprint
	return false, nil
}

