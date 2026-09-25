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
	// FAIL-CLOSED: Guvensiz yapilandirma durumunda worker kesinlikle baslatilamaz
	if token == "" {
		return nil, fmt.Errorf("FAIL-CLOSED: FALCO_WEBHOOK_SECRET env bos olamaz")
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

	// 1. FAIL-CLOSED Webhook Auth: Sabit zamanli karsilastirma (Timing Attack Safe)
	receivedToken := r.Header.Get("X-Falco-Token")
	if subtle.ConstantTimeCompare([]byte(re.authToken), []byte(receivedToken)) != 1 {
		log.Printf("[SECURITY VIOLATION] Gecersiz webhook auth token! Kaynak: %s", r.RemoteAddr)
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

// Semaphore ile Throttling + Panic durumunda Semaphore Sizintisini (Leak) Onleyen Recovery
func (re *RemediationEngine) quarantinePodWithThrottling(namespace, podName, triggerRule string) {
	re.semaphore <- struct{}{}
	defer func() {
		// Panic olsa dahi semaphore serbest birakilir, worker asla kilitlenmez
		if r := recover(); r != nil {
			log.Printf("[PANIC RECOVERED] Karantina goroutine panic yakalandi: %v", r)
		}
		<-re.semaphore
	}()

	re.quarantinePod(namespace, podName, triggerRule)
}

func (re *RemediationEngine) quarantinePod(namespace, podName, triggerRule string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Idempotency Check: Pod zaten karantinada mi?
	pod, err := re.k8sClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Printf("[INFO] Pod zaten sonlanmis: %s/%s", namespace, podName)
			return
		}
		re.escalateFailure(namespace, podName, triggerRule, fmt.Sprintf("Pod bilgisi alinamadi: %v", err))
		return
	}

	if pod.Labels[quarantineLabelKey] == quarantineLabelValue {
		log.Printf("[IDEMPOTENT] Pod zaten karantinada, islem atlandi: %s/%s", namespace, podName)
		return
	}

	log.Printf("[QUARANTINE ACTION] Pod karantinaya aliniyor: %s/%s (Kural: %s)", namespace, podName, triggerRule)

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
			log.Printf("[WARN] Patch conflict engellendi: %s/%s", namespace, podName)
			return
		}
		// Sessiz Basarisizlik Yok: Basarisizlik durumunda eskalasyon uretilir
		re.escalateFailure(namespace, podName, triggerRule, fmt.Sprintf("K8s API Patch basarisiz: %v", err))
		return
	}

	log.Printf("[SUCCESS] Pod basariyla izole edildi (Deny-All devrede): %s/%s", namespace, podName)
}

// Eskalasyon Mekanizmasi:
// Ayrıcalıklı bir worker'a genis internet Egress'i (Slack vb.) acmak Zero-Trust ihlalidir.
// Bunun yerine structured JSON audit event olarak stderr'e yazilir; node logging agent'i (Vector/Fluentbit)
// bunu SIEM ve PagerDuty'ye aninda tasir.
func (re *RemediationEngine) escalateFailure(namespace, podName, rule, reason string) {
	escalationPayload := map[string]interface{}{
		"event_type": "CRITICAL_SECURITY_ESCALATION",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"namespace":  namespace,
		"pod_name":   podName,
		"rule":       rule,
		"reason":     reason,
		"action":     "MANUAL_INCIDENT_INTERVENTION_REQUIRED",
	}

	data, _ := json.Marshal(escalationPayload)
	// Stderr uzerinden unbuffered SIEM audit log
	fmt.Fprintf(os.Stderr, "[ALERT_ESCALATION] %s\n", string(data))
}

func main() {
	log.Println("[BOOT] Falco Active Remediation Worker baslatiliyor...")

	authToken := os.Getenv("FALCO_WEBHOOK_SECRET")
	if authToken == "" {
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
