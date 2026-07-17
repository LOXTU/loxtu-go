/**
 * LOXTU — Passkey Registration & Login
 * Browser-side WebAuthn (passkey) for biometric/FIDO2 authentication.
 * Uses delegated event listeners — works with HTMX dynamic content.
 */
(function () {
  'use strict';

  // Guard: prevent double-initialization (HTMX script re-execution).
  if (window.__passkeyInitialized) return;
  window.__passkeyInitialized = true;

  // ── AbortController for conditional mediation ──
  var conditionalAbortController = null;

  // ── Guard: prevent concurrent registration ──
  var registrationInProgress = false;

  // ── Conditional Mediation (passkey autofill) ──

  // Run on page load: if the login page has autocomplete="username webauthn",
  // fetch discoverable credential options and set up conditional mediation.
  var emailInput = document.querySelector('input[autocomplete="username webauthn"]');
  if (emailInput) {
    checkPasskeyAvailability();
  }

  async function checkPasskeyAvailability() {
    // Check if the browser supports passkeys at all
    if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) {
      console.log('[passkey] Not supported');
      return;
    }

    try {
      var available = await PublicKeyCredential.isConditionalMediationAvailable();
      if (!available) {
        console.log('[passkey] Conditional mediation not available');
        return;
      }
    } catch (err) {
      console.log('[passkey] Conditional mediation check failed:', err);
      return;
    }

    // Conditional mediation IS available → show the passkey icon button
    var pkBtn = document.getElementById('passkey-signin-btn');
    if (pkBtn) {
      pkBtn.style.display = 'flex';
    }

    // Start conditional mediation (autofill in email field)
    setupConditionalMediation();
  }

  async function setupConditionalMediation() {
    // Check if the browser supports conditional mediation
    if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) {
      console.log('[passkey] Conditional mediation not supported');
      return;
    }

    try {
      var available = await PublicKeyCredential.isConditionalMediationAvailable();
      if (!available) {
        console.log('[passkey] Conditional mediation not available');
        return;
      }
    } catch (err) {
      console.log('[passkey] Conditional mediation check failed:', err);
      return;
    }

    try {
      // Create abort controller so explicit sign-in can cancel this
      conditionalAbortController = new AbortController();

      // Step 1: get discoverable credential options from the server
      var resp = await fetch('/auth/passkey/login/begin');
      if (!resp.ok) {
        console.warn('[passkey] Failed to get login options:', await resp.json());
        return;
      }

      var options = await resp.json();
      console.log('[passkey] Received login options, mediation:', options.mediation);

      // Guard: backend returns {status:'no-email'} when no email was sent.
      if (!options || !options.publicKey) {
        console.log('[passkey] Conditional mediation: no credentials found, exiting gracefully.');
        return;
      }

      // Convert challenge and allowCredentials from base64url
      options.publicKey.challenge = base64urlToArrayBuffer(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials.forEach(function (cred) {
          cred.id = base64urlToArrayBuffer(cred.id);
        });
      }

      // Step 2: call get() with conditional mediation — browser shows a
      // non-modal dialog with available passkeys. The promise resolves
      // only when the user selects a credential.
      var assertion = await navigator.credentials.get({
        publicKey: options.publicKey,
        mediation: 'conditional',
        signal: conditionalAbortController.signal,
      });

      if (!assertion) {
        console.log('[passkey] No credential selected');
        return;
      }

      console.log('[passkey] User selected a passkey');

      // Step 3: encode and send to finish endpoint
      var encoded = encodeAssertion(assertion);
      var finishResp = await fetch('/auth/passkey/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(encoded),
      });

      if (!finishResp.ok) {
        var err = await finishResp.json();
        console.error('[passkey] Login failed:', err);
        return;
      }

      console.log('[passkey] Login successful, redirecting...');
      var data = await finishResp.json();
      window.location.href = data.redirect || '/dashboard';

    } catch (err) {
      // Ignore abort errors from explicit sign-in
      if (err.name === 'AbortError') {
        console.log('[passkey] Conditional mediation aborted for explicit sign-in');
        return;
      }
      console.error('[passkey] Conditional mediation error:', err);
    }
  }

  // ── Delegated click handlers ──
  document.addEventListener('click', function (e) {
    var regBtn = e.target.closest('.js-register-passkey');
    if (regBtn) {
      var email = regBtn.getAttribute('data-email');
      if (email) registerPasskey(email);
      return;
    }
    var skipBtn = e.target.closest('.js-skip-passkey');
    if (skipBtn) {
      var email = skipBtn.getAttribute('data-email');
      if (email) skipPasskey(email);
      return;
    }
    var signinBtn = e.target.closest('.js-signin-passkey');
    if (signinBtn) {
      // Abort conditional mediation before starting explicit sign-in
      if (conditionalAbortController) {
        conditionalAbortController.abort();
        conditionalAbortController = null;
      }
      // Read email from the input field if available.
      var emailInput = document.querySelector('input[name="email"]');
      var email = emailInput ? emailInput.value.trim() : '';
      signInWithPasskey(email);
    }
  });

  async function signInWithPasskey(email) {
    console.log('[passkey] Explicit sign-in requested');
    try {
      var url = '/auth/passkey/login/begin';
      if (email) url += '?email=' + encodeURIComponent(email);
      var resp = await fetch(url);
      if (!resp.ok) { console.error('[passkey] Failed to get login options'); return; }
      var options = await resp.json();
      if (!options || !options.publicKey) {
        console.warn('[passkey] No passkey credentials available for this account.');
        alert('No passkey found on this device. Please sign in with OTP instead.');
        return;
      }
      options.publicKey.challenge = base64urlToArrayBuffer(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials.forEach(function (cred) {
          cred.id = base64urlToArrayBuffer(cred.id);
        });
      }
      var assertion = await navigator.credentials.get({ publicKey: options.publicKey });
      var encoded = encodeAssertion(assertion);
      var finishResp = await fetch('/auth/passkey/login/finish', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(encoded),
      });
      if (!finishResp.ok) {
        var err = await finishResp.json();
        console.error('[passkey] Sign-in failed:', err);
        return;
      }
      var data = await finishResp.json();
      window.location.href = data.redirect || '/dashboard';
    } catch (err) {
      console.error('[passkey] Sign-in error:', err);
    }
  }

  async function registerPasskey(email) {
    if (registrationInProgress) {
      console.warn('[passkey] Registration already in progress, ignoring duplicate call.');
      return;
    }
    registrationInProgress = true;
    console.log('[passkey] Starting registration for', email);

    try {
      // Step 1: get registration options from the server
      var body = new URLSearchParams({ email: email });
      var resp = await fetch('/auth/passkey/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body,
      });

      if (!resp.ok) {
        var err = await resp.json();
        console.error('[passkey] Begin registration failed:', err);
        alert('Failed to start passkey registration: ' + (err.error || 'unknown error'));
        return;
      }

      // Step 2: convert server response to PublicKeyCredentialCreationOptions
      var options = await resp.json();
      console.log('[passkey] Received creation options');

      // Convert base64url-encoded fields to ArrayBuffer
      options.publicKey.challenge = base64urlToArrayBuffer(options.publicKey.challenge);
      if (options.publicKey.user && options.publicKey.user.id) {
        options.publicKey.user.id = base64urlToArrayBuffer(options.publicKey.user.id);
      }
      if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials.forEach(function (cred) {
          cred.id = base64urlToArrayBuffer(cred.id);
        });
      }

      // Step 3: call browser's WebAuthn API (Face ID / Touch ID prompt)
      var credential = await navigator.credentials.create({ publicKey: options.publicKey });
      console.log('[passkey] User granted permission, credential created');

      // Step 4: encode the credential response for the server
      var attestation = encodeAttestation(credential);

      // Step 5: send to finish endpoint
      var finishResp = await fetch('/auth/passkey/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(attestation),
      });

      if (!finishResp.ok) {
        var finishErr = await finishResp.json();
        console.error('[passkey] Finish registration failed:', finishErr);
        alert('Passkey registration failed: ' + (finishErr.error || 'unknown error'));
        return;
      }

      console.log('[passkey] Registration complete, redirecting...');

      // Read redirect from JSON body (Go handler returns {status, redirect}).
      var data = await finishResp.json();
      if (data.redirect) {
        window.location.href = data.redirect;
      }

    } catch (err) {
      console.error('[passkey] Error:', err);
      if (err.name === 'NotAllowedError') {
        alert('Passkey setup was cancelled or not allowed.');
      } else if (err.name === 'NotSupportedError') {
        alert('Passkeys are not supported on this device.');
      } else {
        alert('Passkey error: ' + err.message);
      }
    } finally {
      registrationInProgress = false;
    }
  }

  async function skipPasskey(email) {
    console.log('[passkey] Skipping for', email);
    var body = new URLSearchParams({ email: email });
    var resp = await fetch('/auth/passkey/skip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body,
    });

    if (!resp.ok) {
      console.error('[passkey] Skip failed');
      return;
    }

    var data = await resp.json();
    window.location.href = data.redirect || '/dashboard';
  }

  // ── Helpers ──

  function base64urlToArrayBuffer(base64url) {
    var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) base64 += '=';
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function encodeAttestation(credential) {
    return {
      id: credential.id,
      type: credential.type,
      rawId: arrayBufferToBase64url(credential.rawId),
      response: {
        clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
        transports: credential.response.getTransports ? credential.response.getTransports() : [],
      },
    };
  }

  function encodeAssertion(assertion) {
    return {
      id: assertion.id,
      type: assertion.type,
      rawId: arrayBufferToBase64url(assertion.rawId),
      response: {
        clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
        authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
        signature: arrayBufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? arrayBufferToBase64url(assertion.response.userHandle)
          : null,
      },
    };
  }

  function arrayBufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
})();