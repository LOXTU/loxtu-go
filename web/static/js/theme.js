/**
 * LoxTu Go — Theme Toggle
 * IIFE module. Exposes loxtuTheme.toggle() and loxtuTheme.set().
 * Dispatches 'themeChanged' event for aurora.js.
 *
 * Convention: any element with class .theme-toggle-btn triggers toggle on click.
 * The button's <img> src is updated to match the current theme.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'loxtu-theme';
  var moonIcon = '/static/icons/moon.svg';
  var sunIcon  = '/static/icons/sun.svg';

  function getTheme() {
    return document.documentElement.getAttribute('data-theme') || 'dark';
  }

  function updateIcons() {
    var theme = getTheme();
    var src = theme === 'dark' ? moonIcon : sunIcon;
    document.querySelectorAll('.theme-toggle-btn img').forEach(function (img) {
      img.src = src;
    });
  }

  function setTheme(theme, dispatch) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem(STORAGE_KEY, theme); } catch (_) {}
    updateIcons();
    if (dispatch !== false) {
      window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: theme } }));
    }
  }

  function toggle() {
    var current = getTheme();
    setTheme(current === 'dark' ? 'light' : 'dark');
  }

  // Delegate clicks on any .theme-toggle-btn
  function setupToggleButtons() {
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('.theme-toggle-btn');
      if (btn) {
        e.preventDefault();
        toggle();
      }
    });
  }

  // Init: restore saved theme, set up listeners
  function init() {
    var saved;
    try { saved = localStorage.getItem(STORAGE_KEY); } catch (_) {}
    if (saved === 'light' || saved === 'dark') {
      setTheme(saved, false);
    }
    setupToggleButtons();
    // HTMX: re-sync icons after swap (new .theme-toggle-btn may appear)
    document.addEventListener('htmx:afterSwap', updateIcons);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Public API (for programmatic use)
  window.loxtuTheme = { toggle: toggle, set: setTheme, get: getTheme };
})();