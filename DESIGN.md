---
version: 2.0
name: LoxTu Go
description: Aviation ground operations control system with Abyssal Aurora design.
colors:
  primary: "#040B14"
  secondary: "#0B1A2F"
  tertiary: "#2DD4BF"
  accent: "#F4B740"
  neutral: "#F8FAFC"
  glass: "rgba(11, 26, 47, 0.65)"
  glass-heavy: "rgba(11, 26, 47, 0.85)"
  glass-text: "#F8FAFC"
  glass-border: "rgba(255, 255, 255, 0.05)"
  on-primary: "#F8FAFC"
  on-tertiary: "#040B14"
  success: "#2DD4BF"
  warning: "#F4B740"
  error: "#EF4444"
  surface: "#040B14"
  emerald-ice: "#2DD4BF"
  emerald-deep: "#0D9488"
  gold-soft: "#F4B740"
  gold-light: "#FFD166"
typography:
  h1:
    fontFamily: Clash Display
    fontSize: 2.5rem
    fontWeight: 200
    lineHeight: 1.15
    letterSpacing: "-0.02em"
  h2:
    fontFamily: Clash Display
    fontSize: 2rem
    fontWeight: 200
    lineHeight: 1.15
  h3:
    fontFamily: Clash Display
    fontSize: 1.5rem
    fontWeight: 400
    lineHeight: 1.15
  h4:
    fontFamily: Clash Display
    fontSize: 1.125rem
    fontWeight: 500
    lineHeight: 1.15
  body:
    fontFamily: Satoshi
    fontSize: 0.938rem
    lineHeight: 1.6
  small:
    fontFamily: Satoshi
    fontSize: 0.813rem
    lineHeight: 1.4
rounded:
  sm: 10px
  md: 24px
  lg: 28px
  xl: 36px
  full: 9999px
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
---

## Overview

LoxTu Go — система управления наземным обслуживанием в авиации. UI использует **Abyssal Aurora** дизайн-систему: глубокий тёмно-синий фон (#040B14) с переливами бирюзового (#2DD4BF) и золотого (#F4B740), стеклянные карточки (glassmorphism 2.0) и bento-сетку.

## Theme System

Дизайн-система поддерживает две темы:

- **Dark (default):** `:root` — глубокий космический фон (#040B14), бирюзовые/золотые акценты
- **Light:** `[data-theme="light"]` — холодный металлик (#E8ECEF), те же акценты, адаптированные под светлый фон

Переключение темы:
- `localStorage('loxtu-theme')` — сохраняет выбор
- `data-theme` атрибут на `<html>` — управляет CSS-переменными
- JS-событие `themeChanged` — для aurora.js (пересоздание облаков)
- Кнопка `.theme-toggle-btn` — в layout.templ

## Colors (Dark Theme)

- **Primary (#040B14):** Глубокий чёрно-синий — фон страницы
- **Secondary (#0B1A2F):** Тёмно-синий — альтернативный фон, подложка карточек
- **Tertiary (#2DD4BF):** Бирюзовый (emerald ice) — основной акцент, кнопки, фокус
- **Accent (#F4B740):** Золотой (gold soft) — второстепенный акцент, кнопка Fuel Order
- **Neutral (#F8FAFC):** Светлый текст на тёмном фоне
- **Surface (#040B14):** Тёмный фон страницы
- **Glass (rgba(11,26,47,0.65)):** Полупрозрачный слой для карточек
- **Glass Border (rgba(255,255,255,0.05)):** Тонкая граница стеклянных элементов
- **Success (#2DD4BF):** Бирюзовый для статусов «успешно»
- **Warning (#F4B740):** Золотой для предупреждений
- **Error (#EF4444):** Красный для ошибок

## Typography

- **Clash Display** — заголовки (h1-h4), с вариативным весом (200-500)
- **Satoshi** — тело текста, кнопки, подписи

Оба шрифта подключаются через Fontshare CDN.

## Aurora Effect

Фоновый эффект северного сияния состоит из двух частей:

1. **CSS-градиенты (body::before/after):** 4-6 эллиптических радиальных градиентов с разными цветами (бирюзовый, золотой), анимированные `auroraShift` (20-28s)
2. **JS-облака (aurora.js):** 5 полупрозрачных круглых пятен (blur 70-100px), которые:
   - Медленно дрейфуют по экрану (±0.3px/frame)
   - Отталкиваются от курсора (радиус 250px)
   - Притягиваются к карточкам на mouseenter (600ms debounce)
   - Пульсируют вокруг элемента после притяжения
   - Улетают при mouseleave (600ms delay)

## CSS Architecture

CSS разбит на модули в `web/static/css/`:

| Файл | Содержание |
|------|-----------|
| `tokens.css` | CSS-переменные (`:root` + `[data-theme="light"]`) |
| `reset.css` | Базовый сброс (box-sizing, margin) |
| `base.css` | Body, типографика, утилиты, скроллбар |
| `aurora.css` | Фоновые градиенты, `.aurora-attract`, облака |
| `components.css` | Glass, card-glass, btn, input-glass, badge |
| `animations.css` | Keyframes, HTMX-переходы |
| `dashboard.css` | Bento grid, dashboard stats, theme toggle, toast |
| `detail-panel.css` | Слайд-ин панель из правого края |
| `app.css` | `@import` всех модулей |

## 3-Layer Glass System

1. **Light** (inputs, второстепенные элементы): blur 10px, box-shadow слабая
2. **Primary** (карточки, панели): blur 20px, градиентная граница, box-shadow средней силы
3. **Heavy** (модалы, detail panel): blur 40px, box-shadow сильная, непрозрачный фон

## Layout

Bento grid — динамическая сетка с модулями разного размера. Каждый модуль — стеклянная панель.

- **Desktop (≥1024px):** 3 колонки, grid-template-areas (stats ×3, fact span 2 + actions, stats ×2)
- **Tablet (640-1023px):** 2 колонки
- **Mobile (<640px):** 1 колонка

## Components

- `card-glass` — основная стеклянная панель (blur + тень + border + градиентная граница)
- `bento-item` — модуль bento-сетки, чуть легче по эффектам, container queries
- `input-glass` — поле ввода в стеклянном стиле
- `btn-primary` — бирюзовая кнопка с glow-эффектом через ::after
- `btn-secondary` — стеклянная прозрачная кнопка
- `btn-gold` — золотая кнопка
- `badge-emerald/gold/success/error` — цветовые индикаторы
- `toast` — всплывающее уведомление

## Do's and Don'ts

- **Do** использовать CSS-переменные везде — никогда не хардкодить цвета
- **Do** менять только `tokens.css` для смены темы
- **Do** использовать `Base()` из `shared/templates/layout.templ` для всех полных страниц
- **Do** добавлять HTMX-фрагменты (без `<html>/<head>`)
- **Do** поддерживать JSON-ответ через `?format=json` или `Accept: application/json`
- **Don't** злоупотреблять прозрачностью — читаемость важнее эстетики
- **Don't** использовать `background` shorthand для кнопок — используй `background-color`
- **Don't** дублировать стили в разных модулях
