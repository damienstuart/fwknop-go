package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveExternalIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.42\n"))
	}))
	defer srv.Close()

	ip, err := resolveExternalIP(srv.URL)
	if err != nil {
		t.Fatalf("resolveExternalIP error: %v", err)
	}
	if ip != "203.0.113.42" {
		t.Errorf("got %q, want %q", ip, "203.0.113.42")
	}
}

func TestResolveExternalIPInvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-an-ip"))
	}))
	defer srv.Close()

	_, err := resolveExternalIP(srv.URL)
	if err == nil {
		t.Error("expected error for invalid IP response, got nil")
	}
}

func TestResolveExternalIPServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := resolveExternalIP(srv.URL)
	if err == nil {
		t.Error("expected error for HTTP 500, got nil")
	}
}

func TestResolveExternalIPWithWhitespace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("  10.0.0.1  \n"))
	}))
	defer srv.Close()

	ip, err := resolveExternalIP(srv.URL)
	if err != nil {
		t.Fatalf("resolveExternalIP error: %v", err)
	}
	if ip != "10.0.0.1" {
		t.Errorf("got %q, want %q", ip, "10.0.0.1")
	}
}
