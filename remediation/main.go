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

const (
	maxConcurrentQuarantines = 10
	quarantineLabelKey       = "security.quarantine"
	quarantineLabelValue     = "true"
	targetNamespace          = "fintech-gateway"
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
	semaphore chan struct{}
}

func NewRemediationEngine(token string) (*RemediationEngine, error) {
	// FAIL-CLOSED: Token bos ise motor kesinlikle baslatilamaz!
	if token == "" {
		return nil, fmt.Errorf("FAIL-CLOSED: FALCO_WEBHOOK_SECRET bos olamaz, worker guvensiz baslatilamaz")
	}

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
		semaphore: make(chan struct{}, maxConcurrentQuarantines),
	}, nil
}

func (re *RemediationEngine) handleFalcoEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. FAIL-CLOSED Webhook Auth: Header yoksa veya gecersizse aninda 401
	receivedToken := r.Header.Get("X-Falco-Token")
	if subtle.ConstantTimeCompare([]byte(re.authToken), []byte(receivedToken)) != 1 {
		log.Printf("[SECURITY VIOLATION] Gecersiz webhook auth token ile istek reddedildi! Kaynak IP: %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

	if event.Priority == "CRITICAL" || event.Priority == "Emergency" {
		podName, _ := event.OutputFields["k8s.pod.name"].(string)
		namespace, _ := event.OutputFields["k8s.ns.name"].(string)

		// Scope Guard: Sadece fintech-gateway hedeflenebilir
		if namespace == targetNamespace && podName != "" {
			go re.quarantinePodWithThrottling(namespace, podName, event.Rule)
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

// Semaphore ile K8s API'ye goroutine patlamasini engeller (Throttling)
func (re *RemediationEngine) quarantinePodWithThrottling(namespace, podName, triggerRule string) {
	re.semaphore <- struct{}{}
	defer func() { <-re.semaphore }()

	re.quarantinePod(namespace, podName, triggerRule)
}

func (re *RemediationEngine) quarantinePod(namespace, podName, triggerRule string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Idempotency: Zaten karantinada mi?
	pod, err := re.k8sClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Printf("[INFO] Pod zaten sonlanmis, islem atlandi: %s/%s", namespace, podName)
			return
		}
		re.escalateFailure(namespace, podName, triggerRule, fmt.Sprintf("Pod bilgisi alinamadi: %v", err))
		return
	}

	if pod.Labels[quarantineLabelKey] == quarantineLabelValue {
		log.Printf("[IDEMPOTENT] Pod zaten karantinada: %s/%s", namespace, podName)
		return
	}

	log.Printf("[QUARANTINE ACTION] Pod izole ediliyor: %s/%s (Kural: %s)", namespace, podName, triggerRule)

	patchData := []byte(fmt.Sprintf(`{"metadata":{"labels":{"%s":"%s"}}}`, quarantineLabelKey, quarantineLabelValue))

	_, err = re.k8sClient.CoreV1().Pods(namespace).Patch(
		ctx,
		podName,
		types.StrategicMergePatchType,
		patchData,
		metav1.PatchOptions{},
	)

	if err != nil {
		if apierrors.IsConflict(err) {
			log.Printf("[WARN] Patch conflict olustu, yeniden denenmedi (idempotent merge): %s/%s", namespace, podName)
			return
		}
		// 2. ESSIZ BASARISIZLIK ESKALASYONU:
		// Savunma hatti kirildiginda sessiz kalinamaz! SOC/SRE ekibine eskalasyon uretilir.
		re.escalateFailure(namespace, podName, triggerRule, fmt.Sprintf("K8s API Patch basarisiz: %v", err))
		return
	}

	log.Printf("[SUCCESS] Pod basariyla izole edildi (Deny-All devrede): %s/%s", namespace, podName)
}

// Otonom mudahale basarisiz olursa manuel mudahale icin acil eskalasyon alarmi uretir
func (re *RemediationEngine) escalateFailure(namespace, podName, rule, reason string) {
	log.Printf("=====================================================================")
	log.Printf("[CRITICAL ESCALATION] OTOMATIK KARANTINA BASARISIZ OLDU!")
	log.Printf("HEDEF: %s/%s | TETIKLEYEN KURAL: %s", namespace, podName, rule)
	log.Printf("NEDEN: %s", reason)
	log.Printf("AKSIYON GEREKLI: Lutfen pod'u acilen manuel olarak izole edin veya sonlandirin!")
	log.Printf("=====================================================================")
}

func main() {
	log.Println("[BOOT] Falco Active Remediation Worker baslatiliyor...")

	authToken := os.Getenv("FALCO_WEBHOOK_SECRET")
	if authToken == "" {
		// FAIL-CLOSED: Guvensiz yapilandirma durumunda aninda fatal exit
		log.Fatalf("[FATAL CONFIG] FALCO_WEBHOOK_SECRET env bulunamadi! Sistem fail-closed modunda kapaniyor.")
	}

	engine, err := NewRemediationEngine(authToken)
	if err != nil {
		log.Fatalf("[FATAL] Remediation motoru baslatilamadi: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", engine.handleFalcoEvent)
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
		log.Println("[INFO] Remediation Webhook :8080 portunda dinliyor (Fail-Closed Auth AKTIF)...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server hatasi: %v", err)
		}
	}()

	<-stop
	log.Println("[INFO] Graceful shutdown tamamlandi.")
}
