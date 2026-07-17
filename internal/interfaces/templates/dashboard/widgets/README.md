# Dashboard widgets
#
# Package: internal/interfaces/templates/dashboard/widgets
# Rule: import shared/components only — no ad-hoc hex colours.

| Widget | Purpose |
|--------|---------|
| `StatsWidget` | KPI number + label (click → detail panel) |
| `FactWidget` | Narrative tile (crew briefing, notices) |
| `ActionsWidget` | Quick action buttons |
| `RosterWidget` | Crew roster skeleton (Phase 2 fill) |
| `WeatherWidget` | METAR-style snapshot |
| `GanttWidget` | Turnaround timeline empty-state |

`dashboard.DashboardGrid` only composes widgets; layout/classes stay token-driven.
