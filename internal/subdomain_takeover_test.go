package internal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
)

// TODO: Test how invalid responses are handled
func TestGetFingerprints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := []byte(`[
			{
				"cicd_pass": true,
				"cname": ["elasticbeanstalk.com"],
				"discussion": "[Issue #194](https://github.com/EdOverflow/can-i-take-over-xyz/issues/194)",
				"documentation": "",
				"fingerprint": "NXDOMAIN",
				"http_status": null,
				"nxdomain": true,
				"service": "AWS/Elastic Beanstalk",
				"status": "Vulnerable",
				"vulnerable": true
			},
			{
				"cicd_pass": false,
				"cname": ["elb.amazonaws.com"],
				"discussion": "[Issue #137](https://github.com/EdOverflow/can-i-take-over-xyz/issues/137)",
				"documentation": "",
				"fingerprint": "NXDOMAIN",
				"http_status": null,
				"nxdomain": true,
				"service": "AWS/Load Balancer (ELB)",
				"status": "Not vulnerable",
				"vulnerable": false
			}]`)
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	// We expect GetFingerprints to trim the fingerprint with "vulnerable": false
	expectedFingerprints := []Fingerprint{
		 {
			Cname: []string{"elasticbeanstalk.com"},
			Discussion: "[Issue #194](https://github.com/EdOverflow/can-i-take-over-xyz/issues/194)",
			Fingerprint: "NXDOMAIN",
			NXDomain: true,
			Service: "AWS/Elastic Beanstalk",
			Vulnerable: true,
		 },
	}

  client := http.DefaultClient
	fingerprints, err := GetFingerprints(server.URL, client)
	if err != nil {
		t.Error(err)
	}

	for index, fingerprint := range expectedFingerprints {
		if len(fingerprints) != len(expectedFingerprints) {
			t.Errorf("Fingerprints length do not match.\nGot: %d\nExpected: %d", len(fingerprints), len(expectedFingerprints))
		}
		if !fingerprints[index].IsSameAs(fingerprint) {
			t.Errorf("Fingerprints do not match.\nGot: %+v\nExpected: %+v", fingerprints[index], fingerprint)
		}
	}
}

func TestCheckResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer server.Close()

	re, err := regexp.Compile("test")
	if err != nil {
		t.Errorf("failed to compile regex: %v", err)
	}

	vuln, err := checkResponse(server.URL, re, http.DefaultClient)
	if err != nil {
		t.Error(err)
	}

	if vuln != true {
		t.Error("regex not detected in response")
	}
}

func TestCheckURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer server.Close()

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

	vuln, err := CheckURL(server.URL, []Fingerprint{exampleFingerprint}, http.DefaultClient)
	if err != nil {
		t.Error(err)
	}

	if vuln != true {
		t.Error("regex not detected in response")
	}
}