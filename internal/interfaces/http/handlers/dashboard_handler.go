package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/shared/httputil"
	dashtmpl "github.com/loxtu/loxtu-go/internal/interfaces/templates/dashboard"
	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
)

// DashboardHandler serves the ops dashboard with tenant-aware bento widgets.
type DashboardHandler struct {
	tenants interface {
		GetByTenantID(ctx context.Context, tenantID string) (*identity.Tenant, error)
	}
}

// NewDashboardHandler constructs a DashboardHandler.
func NewDashboardHandler() *DashboardHandler { return &DashboardHandler{} }

// NewDashboardHandlerWithTenant constructs a DashboardHandler with tenant store.
func NewDashboardHandlerWithTenant(tenants interface {
	GetByTenantID(ctx context.Context, tenantID string) (*identity.Tenant, error)
}) *DashboardHandler {
	return &DashboardHandler{tenants: tenants}
}

// Mount registers dashboard routes (behind Guard).
func (h *DashboardHandler) Mount(r chi.Router) {
	r.Get("/dashboard", h.Dashboard)
	r.Get("/dashboard/grid", h.Grid)
	r.Get("/dashboard.json", h.JSON)
	r.Get("/dashboard/panel/stats", h.DetailPanel)
	r.Get("/dashboard/panel/close", h.ClosePanel)
}

func (h *DashboardHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	data := h.getDashboardData(r)
	ld, _ := json.Marshal(data)
	email := GetEmail(r)
	if email == "" {
		email = "user@loxtu.com"
	}
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, data)
		return
	}
	templ.Handler(dashtmpl.DashboardShell(email, string(ld))).ServeHTTP(w, r)
}

func (h *DashboardHandler) Grid(w http.ResponseWriter, r *http.Request) {
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, h.getDashboardData(r))
		return
	}
	templ.Handler(dashtmpl.DashboardGrid()).ServeHTTP(w, r)
}

func (h *DashboardHandler) JSON(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, h.getDashboardData(r))
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

// BentoCard is a bento-style dashboard card.
type BentoCard struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	Value string `json:"value,omitempty"`
	Text  string `json:"text,omitempty"`
	Label string `json:"label,omitempty"`
	URL   string `json:"url,omitempty"`
	Icon  string `json:"icon,omitempty"`
}

// DashboardData is serialisable dashboard state.
type DashboardData struct {
	Context  string     `json:"@context"`
	Type     string     `json:"@type"`
	Name     string     `json:"name"`
	TenantID string     `json:"tenant_id"`
	Features []string   `json:"features"`
	Cards    []BentoCard `json:"cards"`
}

// getDashboardData returns tenant-aware bento cards.
func (h *DashboardHandler) getDashboardData(r *http.Request) DashboardData {
	tenantID := mw.GetTenantID(r.Context())
	if tenantID == "" {
		tenantID = "public"
	}

	// Load tenant features
	features := []string{"flights", "crew", "gates", "fuel", "weather", "messages"} // default
	if h.tenants != nil {
		if tenant, err := h.tenants.GetByTenantID(r.Context(), tenantID); err == nil && tenant != nil {
			features = tenant.Features
		}
	}

	// Build bento cards based on features
	var cards []BentoCard
	for _, f := range features {
		switch f {
		case "flights":
			cards = append(cards, BentoCard{Type: "stats", Title: "Active Flights", Value: "12", Label: "currently in operation", Icon: "✈️"})
		case "crew":
			cards = append(cards, BentoCard{Type: "stats", Title: "Crew On Duty", Value: "47", Label: "3 schedule changes", Icon: "👥"})
		case "gates":
			cards = append(cards, BentoCard{Type: "stats", Title: "Gate Utilisation", Value: "87%", Label: "+3% vs yesterday", Icon: "🚪"})
		case "fuel":
			cards = append(cards, BentoCard{Type: "stats", Title: "Fuel Orders", Value: "6", Label: "2 pending delivery", Icon: "⛽"})
		case "weather":
			cards = append(cards, BentoCard{Type: "fact", Title: "Weather Briefing", Text: "METAR EGLL 181250Z 26012KT 9999 FEW045 22/14 Q1015", Icon: "🌤️"})
		case "messages":
			cards = append(cards, BentoCard{Type: "stats", Title: "Messages", Value: "5", Label: "2 urgent", Icon: "💬"})
		case "delay":
			cards = append(cards, BentoCard{Type: "action", Title: "Delay Report", Text: "BA2490 — 45min delay, mechanical. Passenger rebooking initiated.", Icon: "⏱️"})
		case "ramp":
			cards = append(cards, BentoCard{Type: "action", Title: "Ramp Check", Text: "Stand 14 — pushback approved. Ground crew: Team Bravo.", Icon: "🚛"})
		case "on_time":
			cards = append(cards, BentoCard{Type: "stats", Title: "On-Time Rate", Value: "94%", Label: "above target 90%", Icon: "📊"})
		default:
			cards = append(cards, BentoCard{Type: "fact", Title: f, Text: "Feature configured for this tenant.", Icon: "📋"})
		}
	}

	// Always add quick actions
	cards = append(cards, BentoCard{Type: "action", Title: "Quick Actions", Text: "Delay report · Ramp check · Fuel order · Crew swap", Icon: "⚡"})

	return DashboardData{
		Context:  "https://schema.org",
		Type:     "Dashboard",
		Name:     "Loxtu Dashboard",
		TenantID: tenantID,
		Features: features,
		Cards:    cards,
	}
}
