package main

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "sync"
    "testing"

    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
)

func TestQuarantinePodPatchesLabelViaKubernetesAPI(t *testing.T) {
    var mu sync.Mutex
    labels := map[string]string{"app": "trc20-gateway"}
    patched := false

    endpoint := "/api/v1/namespaces/fintech-gateway/pods/demo"
    fakeAPIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != endpoint {
            http.NotFound(w, r)
            return
        }
        switch r.Method {
        case http.MethodGet:
            mu.Lock()
            snapshot := map[string]string{}
            for k, v := range labels { snapshot[k] = v }
            mu.Unlock()
            w.Header().Set("Content-Type", "application/json")
            _ = json.NewEncoder(w).Encode(map[string]any{
                "apiVersion": "v1", "kind": "Pod",
                "metadata": map[string]any{"name": "demo", "namespace": "fintech-gateway", "labels": snapshot},
            })
        case http.MethodPatch:
            body, _ := io.ReadAll(r.Body)
            var patch struct {
                Metadata struct {
                    Labels map[string]string `json:"labels"`
                } `json:"metadata"`
            }
            if err := json.Unmarshal(body, &patch); err != nil {
                http.Error(w, "Bad Patch", http.StatusBadRequest)
                return
            }
            mu.Lock()
            for k,v := range patch.Metadata.Labels { labels[k] = v }
            patched = true
            mu.Unlock()
            w.Header().Set("Content-Type", "application/json")
            _ = json.NewEncoder(w).Encode(map[string]any{
                "apiVersion": "v1", "kind": "Pod",
                "metadata": map[string]any{"name": "demo", "namespace": "fintech-gateway", "labels": labels},
            })
        default:
            http.Error(w, "Unsupported", http.StatusMethodNotAllowed)
        }
    }))
    defer fakeAPIServer.Close()

    client, err := kubernetes.NewForConfig(&rest.Config{Host: fakeAPIServer.URL})
    if err != nil { t.Fatal(err) }

    engine := &RemediationEngine{k8sClient: client, semaphore: make(chan struct{}, maxConcurrentQuarantines)}
    engine.quarantinePod("fintech-gateway", "demo", "TestRule")

    mu.Lock()
    defer mu.Unlock()
    if !patched || labels[quarantineLabelKey] != quarantineLabelValue {
        t.Fatalf("pod label was not applied; patched=%v labels=%v", patched, labels)
    }
}

func TestRemediationOverloadRejectsWithoutStartingWork(t *testing.T) {
    engine := &RemediationEngine{authToken: "unit-test-secret", semaphore: make(chan struct{}, 1)}
    engine.semaphore <- struct{}{} // All permitted slots already occupied.
    event := []byte(`{"priority":"CRITICAL","rule":"BadProcess","output_fields":{"k8s.ns.name":"fintech-gateway","k8s.pod.name":"demo"}}`)
    req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(event))
    req.Header.Set("X-Falco-Token", "unit-test-secret")
    recorder := httptest.NewRecorder()
    engine.handleFalcoEvent(recorder, req)
    if recorder.Code != http.StatusServiceUnavailable {
        t.Fatalf("expected overloaded webhook 503, got %d", recorder.Code)
    }
}
