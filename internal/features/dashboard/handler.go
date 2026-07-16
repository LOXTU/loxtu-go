package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"github.com/loxtu/loxtu-go/internal/features/auth"
	"github.com/loxtu/loxtu-go/internal/features/shared/httputil"
)

// Mount registers dashboard routes.
func Mount(r chi.Router) {
	r.Get("/dashboard", HandleDashboard)
	r.Get("/dashboard/grid", HandleDashboardGrid)
	r.Get("/dashboard.json", HandleDashboardJSON)
	r.Get("/dashboard/panel/stats", HandleDetailPanel)
	r.Get("/dashboard/panel/close", HandleClosePanel)
}

func HandleDashboard(w http.ResponseWriter, r *http.Request) {
	data := GetData()
	ld, _ := json.Marshal(data)
	email := auth.GetEmail(r)
	if email == "" {
		email = "user@airline.com"
	}
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, data)
		return
	}
	templ.Handler(DashboardShell(email, string(ld))).ServeHTTP(w, r)
}

func HandleDashboardGrid(w http.ResponseWriter, r *http.Request) {
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, GetData())
		return
	}
	templ.Handler(DashboardGrid()).ServeHTTP(w, r)
}

func HandleDashboardJSON(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, GetData())
}

func HandleDetailPanel(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	value := r.URL.Query().Get("value")
	label := r.URL.Query().Get("label")
	detail := fmt.Sprintf("Detailed information about %s. Current value is %s. %s", title, value, label)

	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"title": title, "value": value, "label": label, "detail": detail})
		return
	}

	// Trigger JS to add .open classes to panel and overlay
	w.Header().Set("HX-Trigger-After-Swap", `{"openDetailPanel":true}`)
	templ.Handler(DetailPanelContent(title, value, label, detail)).ServeHTTP(w, r)
}

func HandleClosePanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("HX-Trigger-After-Swap", `{"closeDetailPanel":true}`)
	w.Write([]byte(""))
}