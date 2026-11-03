package main

import (
    "bytes"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestWebhookRejectsUnauthorizedRequest(t *testing.T) {
    engine := &RemediationEngine{authToken: "test-only-secret", semaphore: make(chan struct{}, maxConcurrentQuarantines)}
    req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewBufferString("{}"))
    req.Header.Set("X-Falco-Token", "invalid")
    recorder := httptest.NewRecorder()
    engine.handleFalcoEvent(recorder, req)
    if recorder.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d", recorder.Code)
    }
}

func TestWebhookRejectsOversizedPayload(t *testing.T) {
    engine := &RemediationEngine{authToken: "test-only-secret", semaphore: make(chan struct{}, maxConcurrentQuarantines)}
    req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(bytes.Repeat([]byte("x"), (1<<20)+1)))
    req.Header.Set("X-Falco-Token", "test-only-secret")
    recorder := httptest.NewRecorder()
    engine.handleFalcoEvent(recorder, req)
    if recorder.Code != http.StatusRequestEntityTooLarge {
        t.Fatalf("expected 413, got %d", recorder.Code)
    }
}

func TestWebhookAcceptsNoncriticalEvent(t *testing.T) {
    engine := &RemediationEngine{authToken: "test-only-secret", semaphore: make(chan struct{}, maxConcurrentQuarantines)}
    req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewBufferString(`{"rule":"demo-rule","priority":"INFO","output_fields":{}}`))
    req.Header.Set("X-Falco-Token", "test-only-secret")
    recorder := httptest.NewRecorder()
    engine.handleFalcoEvent(recorder, req)
    if recorder.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", recorder.Code)
    }
}
