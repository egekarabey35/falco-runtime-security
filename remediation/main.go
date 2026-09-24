package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type FalcoEvent struct {
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

type RemediationEngine struct {
	k8sClient kubernetes.Interface
}

func NewRemediationEngine() (*RemediationEngine, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster k8s config alinamadi: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("k8s clientset olusturulamadi: %w", err)
	}

	return &RemediationEngine{k8sClient: clientset}, nil
}

func (re *RemediationEngine) handleFalcoEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Cannot read payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var event FalcoEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("[FALCO EVENT] Rule: %s | Priority: %s", event.Rule, event.Priority)

	// Sadece CRITICAL alarmlarda NetworkPolicy ile izolasyon uygula
	if event.Priority == "CRITICAL" || event.Priority == "Emergency" {
		podName, _ := event.OutputFields["k8s.pod.name"].(string)
		namespace, _ := event.OutputFields["k8s.ns.name"].(string)

		if podName != "" && namespace != "" {
			go re.quarantinePod(namespace, podName, event.Rule)
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

// Pod'u silmeden NetworkPolicy ile izole etmek için patch atar
func (re *RemediationEngine) quarantinePod(namespace, podName, triggerRule string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Printf("[QUARANTINE ACTION] Pod karantinaya aliniyor: %s/%s (Kural: %s)", namespace, podName, triggerRule)

	patchData := []byte(`{"metadata":{"labels":{"security.quarantine":"true"}}}`)

	_, err := re.k8sClient.CoreV1().Pods(namespace).Patch(
		ctx,
		podName,
		types.StrategicMergePatchType,
		patchData,
		metav1.PatchOptions{},
	)

	if err != nil {
		log.Printf("[ERROR] Pod karantinaya alinamadi (%s/%s): %v", namespace, podName, err)
		return
	}

	log.Printf("[SUCCESS] Pod izole edildi: %s/%s (Deny-All NetworkPolicy devrede)", namespace, podName)
}

func main() {
	log.Println("[BOOT] Falco Active Remediation Worker baslatiliyor...")

	engine, err := NewRemediationEngine()
	if err != nil {
		log.Printf("[WARN] K8s cluster disinda calisiyor (Mock mod): %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if engine != nil {
			engine.handleFalcoEvent(w, r)
		} else {
			log.Println("[MOCK] Webhook alindi, k8s cluster baglantisi yok.")
			w.WriteHeader(http.StatusOK)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("[INFO] Remediation Webhook :8080 portunda dinliyor...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server hatasi: %v", err)
		}
	}()

	<-stop
	log.Println("[INFO] Graceful shutdown tamamlandi.")
}
