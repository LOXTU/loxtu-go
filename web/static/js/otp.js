/**
 * LOXTU — OTP Auto-Submit
 * 6-box OTP input with auto-focus and auto-submit on fill.
 * Uses event delegation — works with HTMX dynamic swaps.
 */
(function () {
  'use strict';

  var BOXES_SEL = '.otp-boxes[role="group"]';
  var BOX_SEL = '.otp-box';

  function isOtpBox(el) {
    return el && el.matches && el.matches(BOX_SEL);
  }

  // Digit input: auto-advance to next box
  function handleInput(e) {
    var input = e.target;
    if (!isOtpBox(input)) return;
    var val = input.value.replace(/\D/g, '');
    if (val.length > 1) val = val.slice(-1);
    input.value = val;

    if (val.length === 1) {
      var next = input.nextElementSibling;
      if (isOtpBox(next)) { next.focus(); next.select(); }
    }
  }

  // Paste: spread across boxes then auto-submit
  function handlePaste(e) {
    var input = e.target;
    if (!isOtpBox(input)) return;
    var paste = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
    if (paste.length === 0) return;
    e.preventDefault();

    var boxes = input.closest(BOXES_SEL);
    if (!boxes) return;
    var all = boxes.querySelectorAll(BOX_SEL);
    for (var i = 0; i < all.length && i < paste.length; i++) {
      all[i].value = paste[i];
    }
    var lastIdx = Math.min(paste.length, all.length) - 1;
    all[lastIdx].focus();
    all[lastIdx].select();

    // Auto-submit if all filled after paste
    trySubmit(boxes);
  }

  // Backspace: go back. Enter: force submit via HTMX.
  function handleKeydown(e) {
    var input = e.target;
    if (!isOtpBox(input)) return;
    if (e.key === 'Backspace' && input.value === '') {
      var prev = input.previousElementSibling;
      if (isOtpBox(prev)) { prev.focus(); prev.select(); }
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      var boxes = input.closest(BOXES_SEL);
      if (boxes) {
        var form = boxes.closest('form');
        if (form) {
          if (window.htmx) {
            htmx.trigger(form, 'submit');
          } else {
            form.requestSubmit();
          }
        }
      }
    }
  }

  // Check all boxes filled + submit via HTMX
  function trySubmit(boxes) {
    if (!boxes) return;
    var all = boxes.querySelectorAll(BOX_SEL);
    for (var i = 0; i < all.length; i++) {
      if (all[i].value === '') return;
    }
    var form = boxes.closest('form');
    if (form) {
      // Use HTMX to trigger submit (preserving hx-post attributes)
      if (window.htmx) {
        htmx.trigger(form, 'submit');
      } else {
        form.requestSubmit();
      }
    }
  }

  // Input → after value set, check auto-submit
  function onInput(e) {
    handleInput(e);
    var input = e.target;
    if (isOtpBox(input)) {
      var boxes = input.closest(BOXES_SEL);
      trySubmit(boxes);
    }
  }

  function init() {
    document.addEventListener('input', onInput);
    document.addEventListener('paste', handlePaste);
    document.addEventListener('keydown', handleKeydown);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();