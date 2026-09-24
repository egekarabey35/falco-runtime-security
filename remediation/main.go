package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	authToken string
}

func NewRemediationEngine(token string) (*RemediationEngine, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster k8s config alinamadi: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("k8s clientset olusturulamadi: %w", err)
	}

	return &RemediationEngine{
		k8sClient: clientset,
		authToken: token,
	}, nil
}

func (re *RemediationEngine) handleFalcoEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Webhook Auth (Shared-Secret / Timing Attack Safe)
	// Cluster içi yetkisiz pod'ların sahte alert atıp DoS yaratmasını engeller
	receivedToken := r.Header.Get("X-Falco-Token")
	if re.authToken != "" {
		if subtle.ConstantTimeCompare([]byte(re.authToken), []byte(receivedToken)) != 1 {
			log.Printf("[SECURITY WARN] Gecersiz webhook token ile istek reddedildi! IP: %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
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

	// Sadece CRITICAL veya Emergency seviyesinde ve fintech-gateway namespace'ine kısıtlı aksiyon
	if event.Priority == "CRITICAL" || event.Priority == "Emergency" {
		podName, _ := event.OutputFields["k8s.pod.name"].(string)
		namespace, _ := event.OutputFields["k8s.ns.name"].(string)

		// Scope sınırlandırması: Worker sadece fintech-gateway namespace'ine müdahale edebilir
		if namespace == "fintech-gateway" && podName != "" {
			go re.quarantinePod(namespace, podName, event.Rule)
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

// Pod'u silmeden NetworkPolicy ile izole etmek için patch uygular
func (re *RemediationEngine) quarantinePod(namespace, podName, triggerRule string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 2. Idempotency Check: Pod zaten karantinada mı? Peş peşe gelen alert'lerde gereksiz patch ve conflict önlenir.
	pod, err := re.k8sClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Printf("[WARN] Pod bulunamadi, muhtemelen sonlandi: %s/%s", namespace, podName)
			return
		}
		log.Printf("[ERROR] Pod bilgisi alinamadi (%s/%s): %v", namespace, podName, err)
		return
	}

	if pod.Labels["security.quarantine"] == "true" {
		log.Printf("[IDEMPOTENT] Pod zaten karantinada, islem atlandi: %s/%s", namespace, podName)
		return
	}

	log.Printf("[QUARANTINE ACTION] Pod karantinaya aliniyor: %s/%s (Kural: %s)", namespace, podName, triggerRule)

	patchData := []byte(`{"metadata":{"labels":{"security.quarantine":"true"}}}`)

	// 3. StrategicMergePatch ile etiket basımı (Conflict ve race safe)
	_, err = re.k8sClient.CoreV1().Pods(namespace).Patch(
		ctx,
		podName,
		types.StrategicMergePatchType,
		patchData,
		metav1.PatchOptions{},
	)

	if err != nil {
		if apierrors.IsConflict(err) {
			log.Printf("[WARN] Patch conflict olustu, baska bir operasyonla cakisildi (%s/%s)", namespace, podName)
			return
		}
		log.Printf("[ERROR] Pod karantinaya alinamadi (%s/%s): %v", namespace, podName, err)
		return
	}

	log.Printf("[SUCCESS] Pod izole edildi: %s/%s (Deny-All NetworkPolicy devrede)", namespace, podName)
}

func main() {
	log.Println("[BOOT] Falco Active Remediation Worker baslatiliyor...")

	authToken := os.Getenv("FALCO_WEBHOOK_SECRET")
	if authToken == "" {
		log.Println("[WARN] FALCO_WEBHOOK_SECRET tanimli degil, token kontrolu yapilmayacak!")
	}

	engine, err := NewRemediationEngine(authToken)
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
