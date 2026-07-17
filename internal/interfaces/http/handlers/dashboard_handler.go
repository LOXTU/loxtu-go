package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"github.com/loxtu/loxtu-go/internal/shared/httputil"
	dashtmpl "github.com/loxtu/loxtu-go/internal/interfaces/templates/dashboard"
)

// DashboardHandler serves the ops dashboard (preview data until domain service exists).
type DashboardHandler struct{}

// NewDashboardHandler constructs a DashboardHandler.
func NewDashboardHandler() *DashboardHandler { return &DashboardHandler{} }

// Mount registers dashboard routes (behind Guard).
func (h *DashboardHandler) Mount(r chi.Router) {
	r.Get("/dashboard", h.Dashboard)
	r.Get("/dashboard/grid", h.Grid)
	r.Get("/dashboard.json", h.JSON)
	r.Get("/dashboard/panel/stats", h.DetailPanel)
	r.Get("/dashboard/panel/close", h.ClosePanel)
}

func (h *DashboardHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	data := GetDashboardData()
	ld, _ := json.Marshal(data)
	email := GetEmail(r)
	if email == "" {
		email = "user@airline.com"
	}
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, data)
		return
	}
	templ.Handler(dashtmpl.DashboardShell(email, string(ld))).ServeHTTP(w, r)
}

func (h *DashboardHandler) Grid(w http.ResponseWriter, r *http.Request) {
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, GetDashboardData())
		return
	}
	templ.Handler(dashtmpl.DashboardGrid()).ServeHTTP(w, r)
}

func (h *DashboardHandler) JSON(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, GetDashboardData())
}

func (h *DashboardHandler) DetailPanel(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	value := r.URL.Query().Get("value")
	label := r.URL.Query().Get("label")
	detail := fmt.Sprintf("Detailed information about %s. Current value is %s. %s", title, value, label)
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"title": title, "value": value, "label": label, "detail": detail})
		return
	}
	w.Header().Set("HX-Trigger-After-Swap", `{"openDetailPanel":true}`)
	templ.Handler(dashtmpl.DetailPanelContent(title, value, label, detail)).ServeHTTP(w, r)
}

func (h *DashboardHandler) ClosePanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("HX-Trigger-After-Swap", `{"closeDetailPanel":true}`)
	_, _ = w.Write([]byte(""))
}

// CardData is a bento card payload.
type CardData struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	Value string `json:"value,omitempty"`
	Text  string `json:"text,omitempty"`
	Label string `json:"label,omitempty"`
	URL   string `json:"url,omitempty"`
}

// DashboardData is serialisable dashboard state.
type DashboardData struct {
	Context string     `json:"@context"`
	Type    string     `json:"@type"`
	Name    string     `json:"name"`
	Cards   []CardData `json:"cards"`
}

// GetDashboardData returns preview cards (TODO: SurrealDB-backed service).
func GetDashboardData() DashboardData {
	return DashboardData{
		Context: "https://schema.org",
		Type:    "Dashboard",
		Name:    "Loxtu Dashboard",
		Cards: []CardData{
			{Type: "stats", Title: "Active Flights", Value: "12", Label: "currently in operation"},
			{Type: "stats", Title: "Gate Utilisation", Value: "87%", Label: "+3% vs yesterday"},
			{Type: "stats", Title: "On-Time Rate", Value: "94%", Label: "above target"},
			{Type: "fact", Title: "Crew Briefing", Text: "3 crew schedule changes in the next hour. Review at 14:00."},
			{Type: "action", Title: "Quick Actions", Text: "Delay report · Ramp check · Fuel order"},
			{Type: "stats", Title: "Messages", Value: "5", Label: "2 urgent"},
		},
	}
}
