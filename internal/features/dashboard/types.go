package dashboard

// CardData represents a bento card's payload (used for both HTML and JSON rendering).
type CardData struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	Value string `json:"value,omitempty"`
	Text  string `json:"text,omitempty"`
	Label string `json:"label,omitempty"`
	URL   string `json:"url,omitempty"`
}

// DashboardData is the full dashboard state, serialisable to JSON-LD.
type DashboardData struct {
	Context string     `json:"@context"`
	Type    string     `json:"@type"`
	Name    string     `json:"name"`
	Cards   []CardData `json:"cards"`
}

// GetData returns hardcoded preview data. TODO: load from SurrealDB.
func GetData() DashboardData {
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