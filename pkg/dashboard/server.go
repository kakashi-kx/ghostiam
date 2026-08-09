package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

//go:embed templates/*.html
var templateFS embed.FS

// SSEMessage is the payload broadcast to every connected SSE client.
type SSEMessage struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

// PageData is the context passed to every page template.
type PageData struct {
	PageTitle     string
	ActiveNav     string
	APIKey        string
	Error         string
	Stats         *StatsView
	Charts        *ChartData
	Ghosts        []Ghost
	Alerts        []Alert
	Journeys      []Journey
	Journey       *Journey
	JourneySteps  []JourneyStepView
	MitreTactics  []string
	Seeds         []Seed
	MeshGroups    []MeshGroupView
	Report        *DashboardReport
	SyncNote      string
	DemoGhostUser string
}

// ChartData carries pre-encoded Chart.js datasets for the home page.
type ChartData struct {
	RiskJSON   string
	ByHourJSON string
	ActionsJSON string
}

// StatsView carries all numbers shown on the dashboard home page.
type StatsView struct {
	Ghosts           int
	GhostsActive     int
	GhostsTriggered  int
	AlertsTotal      int
	AlertsToday      int
	Journeys         int
	MeshGroups       int
	Seeds            int
	RiskDistribution map[string]int
	TopActions       []ActionCount
	TopIPs           []IPCount
	AlertsByHour     []HourCount
}

// DashboardServer is the HTTP server backing the GhostIam dashboard.
type DashboardServer struct {
	db        *DB
	router    *mux.Router
	apiKey    string
	port      int
	templates *pageTemplates

	mu         sync.RWMutex
	sseClients map[string]chan SSEMessage
	sseSeq     int64

	httpSrv *http.Server
}

// NewDashboardServer opens the SQLite store, loads templates, and builds the
// router. Pass an empty apiKey to disable authentication.
func NewDashboardServer(dbPath, apiKey string, port int) (*DashboardServer, error) {
	db, err := OpenDB(dbPath)
	if err != nil {
		return nil, err
	}
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	s := &DashboardServer{
		db:         db,
		apiKey:     apiKey,
		port:       port,
		templates:  tmpl,
		sseClients: map[string]chan SSEMessage{},
	}
	s.buildRouter()
	return s, nil
}

// Start begins serving and blocks until the server stops. It returns an error
// if the listener fails to bind.
func (s *DashboardServer) Start() error {
	s.httpSrv = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s.httpSrv.ListenAndServe()
}

// Stop gracefully shuts the server down.
func (s *DashboardServer) Stop() {
	if s.httpSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.httpSrv.Shutdown(ctx)
}

// Publish fans a message out to every connected SSE client.
func (s *DashboardServer) Publish(msg SSEMessage) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
}

// buildRouter registers every dashboard and API route.
func (s *DashboardServer) buildRouter() {
	r := mux.NewRouter()
	r.Use(s.recoverMiddleware)
	r.Use(s.securityHeaders)

	auth := s.requireAPIKey

	r.HandleFunc("/", auth(s.handleIndex)).Methods("GET")
	r.HandleFunc("/ghosts", auth(s.handleGhosts)).Methods("GET")
	r.HandleFunc("/ghosts/deploy", auth(s.handleGhostDeploy)).Methods("POST")
	r.HandleFunc("/ghosts/{username}/delete", auth(s.handleGhostDelete)).Methods("POST")

	r.HandleFunc("/alerts", auth(s.handleAlerts)).Methods("GET")
	r.HandleFunc("/alerts/stream", auth(s.handleAlertStream)).Methods("GET")
	r.HandleFunc("/alerts/simulate", auth(s.handleAlertSimulate)).Methods("POST")

	r.HandleFunc("/journeys", auth(s.handleJourneys)).Methods("GET")
	r.HandleFunc("/journeys/{id}", auth(s.handleJourneyDetail)).Methods("GET")
	r.HandleFunc("/journeys/{id}/mermaid", auth(s.handleJourneyMermaid)).Methods("GET")

	r.HandleFunc("/mesh", auth(s.handleMesh)).Methods("GET")
	r.HandleFunc("/mesh/sync", auth(s.handleMeshSync)).Methods("POST")

	r.HandleFunc("/seeds", auth(s.handleSeeds)).Methods("GET")
	r.HandleFunc("/seeds/seed", auth(s.handleSeedCreate)).Methods("POST")

	r.HandleFunc("/reports/export", auth(s.handleReportExport)).Methods("GET")

	r.HandleFunc("/partials/stats", auth(s.handleStatsPartial)).Methods("GET")
	r.HandleFunc("/partials/alerts", auth(s.handleAlertsPartial)).Methods("GET")

	r.HandleFunc("/api/v1/stats", auth(s.handleAPIStats)).Methods("GET")
	r.HandleFunc("/api/v1/ghosts", auth(s.handleAPIGhosts)).Methods("GET")
	r.HandleFunc("/api/v1/alerts", auth(s.handleCreateAlert)).Methods("POST")
	r.HandleFunc("/api/v1/alerts", auth(s.handleAPIAlerts)).Methods("GET")
	r.HandleFunc("/api/v1/alerts/simulate", auth(s.handleAPISimulateAlert)).Methods("POST")
	r.HandleFunc("/api/v1/journeys", auth(s.handleAPIJourneys)).Methods("GET")
	r.HandleFunc("/api/v1/events", auth(s.handleAPIEvents)).Methods("POST")

	s.router = r
}

// requireAPIKey enforces the shared API key via cookie, query parameter, or
// header, in that order. On success it plants a cookie so nav links work.
func (s *DashboardServer) requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" {
			next(w, r)
			return
		}

		key := ""
		if c, err := r.Cookie("ghostiam_key"); err == nil {
			key = c.Value
		}
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		if key == "" {
			key = r.Header.Get("X-API-Key")
		}

		if subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) != 1 {
			if wantsJSON(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			} else {
				http.Error(w, "Unauthorized — pass ?api_key=, the ghostiam_key cookie, or X-API-Key", http.StatusUnauthorized)
			}
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "ghostiam_key",
			Value:    s.apiKey,
			Path:     "/",
			MaxAge:   86400 * 7,
			SameSite: http.SameSiteLaxMode,
		})
		next(w, r)
	}
}

// recoverMiddleware converts panics into 500 responses instead of killing the
// whole server.
func (s *DashboardServer) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *DashboardServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// handleAlertStream is the Server-Sent Events endpoint. Events are JSON lines
// of the form "data: {...}\n\n".
func (s *DashboardServer) handleAlertStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan SSEMessage, 16)

	s.mu.Lock()
	s.sseSeq++
	id := fmt.Sprintf("client-%d", s.sseSeq)
	s.sseClients[id] = ch
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sseClients, id)
		s.mu.Unlock()
	}()

	// Heartbeat keeps proxies and browsers from dropping the connection.
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	// Initial "connected" event tells the browser the stream is live.
	connected, _ := json.Marshal(SSEMessage{Type: "connected", Payload: map[string]string{"status": "ok"}})
	fmt.Fprintf(w, "retry: 3000\n\nevent: message\ndata: %s\n\n", connected)
	flusher.Flush()

	for {
		select {
		case msg := <-ch:
			data, _ := json.Marshal(msg)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// render executes a named page template with the shared layout.
func (s *DashboardServer) render(w http.ResponseWriter, tmpl *template.Template, data PageData) {
	if data.APIKey == "" {
		data.APIKey = s.apiKey
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// wantsJSON reports whether the request prefers a JSON response.
func wantsJSON(r *http.Request) bool {
	for _, a := range r.Header.Values("Accept") {
		if len(a) >= 0 {
			return a == "application/json" || containsSubstring(a, "json")
		}
	}
	return r.URL.Query().Get("format") == "json"
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
