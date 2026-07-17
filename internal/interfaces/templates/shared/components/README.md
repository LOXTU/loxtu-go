# LOXTU design system — shared templ components
#
# Package: github.com/loxtu/loxtu-go/internal/interfaces/templates/shared/components
# Styling: CSS classes only; colours/spacing from web/static/css/tokens.css (+ components.css).

## Layout

| Component | API | Variants |
|-----------|-----|----------|
| `Container` | `Container(size string)` + children | `sm` `md` `lg` `full` |
| `BentoGrid` | `BentoGrid()` + children | — |
| `BentoItem` | `BentoItem(area string, clickable bool)` + children | area → `bento-card-{area}` |
| `Card` | `Card(elevation string, hover bool)` + children | elevation: `light` `default` `heavy` |
| `CardAuth` | `CardAuth()` + children | auth form shell (`#auth-container`) |
| `Divider` | `Divider(orientation string)` | `horizontal` `vertical` |

## Forms

| Component | API | Notes |
|-----------|-----|-------|
| `Button` | `Button(variant, typeAttr, disabled, loading, fullWidth)` + children | `primary` `secondary` `ghost` `danger` `gold` |
| `ButtonLink` | `ButtonLink(variant, href, fullWidth)` + children | anchor-as-button |
| `InputField` | `InputField(name, inputType, label, placeholder, value, errMsg, disabled, helper, autocomplete, autofocus)` | errMsg shows error state |
| `TextareaField` | `TextareaField(name, label, placeholder, value, rows, errMsg, disabled)` | |
| `SelectField` | `SelectField(name, label, options []SelectOption, selected, disabled)` | `SelectOption{Value,Label}` |
| `Checkbox` | `Checkbox(id, name, title, description, checked, required)` | consent-style |
| `Switch` | `Switch(id, name, label, checked, disabled)` | toggle |

## Feedback

| Component | API | Variants |
|-----------|-----|----------|
| `Badge` | `Badge(variant, text)` | success/emerald, warning/gold, error, info, neutral |
| `BadgeBackdrop` | `BadgeBackdrop(variant)` + children | soft tint behind content |
| `Alert` | `Alert(variant, title, message)` | success error info warning |
| `Toast` | `Toast(id, variant, message)` | dismiss via `[data-toast-dismiss]` |
| `Skeleton` | `Skeleton(lines int)` | 1–6 lines |
| `Spinner` | `Spinner(size)` | `sm` `md` `lg` |
| `EmptyState` | `EmptyState(title, message)` + children | CTA slot via children |

## Navigation & content

| Component | API |
|-----------|-----|
| `LabelText` | `LabelText(variant, text)` — warning error success info muted default |
| `Heading1`…`Heading6` | typography |
| `Text` | `Text(variant, text)` — body secondary muted bold code |
| `Avatar` | `Avatar(src, initials, size)` — image or initials |
| `Icon` | `Icon(name, size, alt)` — `/static/icons/{name}.svg` |
| `Link` | `Link(href, variant, text)` — primary muted danger |
| `Breadcrumb` | `Breadcrumb([]BreadcrumbItem)` |
| `Tabs` | `Tabs([]TabItem, activeID)` |
| `Tooltip` | `Tooltip(text)` + children |
| `Modal` | `Modal(id, title)` + children — close via `[data-modal-close]` |
| `Table` | `Table([]TableColumn, []TableRow, caption)` |

## Rules

1. **No hardcoded hex colours** in components — tokens / `ds-*` / existing glass classes only.
2. Import: `"github.com/loxtu/loxtu-go/internal/interfaces/templates/shared/components"`.
3. Prefer properties over style attributes when adding visuals.
