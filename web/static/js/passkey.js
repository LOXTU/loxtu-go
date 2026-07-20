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

  // ── Delegated click handlers ──
  document.addEventListener('click', function (e) {
    var regBtn = e.target.closest('.js-register-passkey');
    if (regBtn) {
      e.preventDefault();
      var userIDHash = regBtn.getAttribute('data-user-id-hash');
      if (userIDHash) registerPasskey(userIDHash);
      return;
    }
    var signinBtn = e.target.closest('.js-signin-passkey');
    if (signinBtn) {
      e.preventDefault();
      if (conditionalAbortController) {
        conditionalAbortController.abort();
        conditionalAbortController = null;
      }
      var emailInput = document.querySelector('input[name="email"]');
      var email = emailInput ? emailInput.value.trim() : '';
      signInWithPasskey(email);
    }
  });

  // ── Conditional mediation — only on login page with email input ──
  var emailInput = document.querySelector('input[autocomplete="username webauthn"]');
  if (emailInput) {
    setupConditionalMediation();
  }

  async function setupConditionalMediation() {
    if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) {
      return;
    }
    try {
      var available = await PublicKeyCredential.isConditionalMediationAvailable();
      if (!available) return;
    } catch (err) {
      return;
    }

    // Show passkey button
    var pkBtn = document.getElementById('passkey-signin-btn');
    if (pkBtn) pkBtn.style.display = 'flex';

    try {
      conditionalAbortController = new AbortController();

      // Get discoverable credential options
      var resp = await fetch('/auth/passkey/login/begin');
      if (!resp.ok) return;

      var options = await resp.json();
      if (!options || !options.publicKey) return;

      // Convert base64url fields
      options.publicKey.challenge = base64urlToArrayBuffer(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials.forEach(function (cred) {
          cred.id = base64urlToArrayBuffer(cred.id);
        });
      }

      // Conditional mediation — browser shows passkey autofill
      var assertion = await navigator.credentials.get({
        publicKey: options.publicKey,
        mediation: 'conditional',
        signal: conditionalAbortController.signal,
      });

      if (!assertion) return;

      // Send to finish
      var encoded = encodeAssertion(assertion);
      var finishResp = await fetch('/auth/passkey/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(encoded),
      });

      if (!finishResp.ok) return;

      var data = await finishResp.json();
      window.location.href = data.redirect || '/dashboard';
    } catch (err) {
      if (err.name === 'AbortError') return; // Expected when user starts explicit sign-in
      console.error('[passkey] Conditional mediation error:', err);
    }
  }

  async function signInWithPasskey(email) {
    console.log('[passkey] Explicit sign-in requested');
    try {
      var url = '/auth/passkey/login/begin';
      if (email) url += '?email=' + encodeURIComponent(email);
      var resp = await fetch(url);
      if (!resp.ok) { console.error('[passkey] Failed to get login options'); return; }
      var options = await resp.json();
      if (!options || !options.publicKey) {
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
      var finishResp = await fetch('/auth/passkey/login/finish?email=' + encodeURIComponent(email), {
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

  async function registerPasskey(userIDHash) {
    if (registrationInProgress) {
      console.warn('[passkey] Registration already in progress, ignoring.');
      return;
    }
    registrationInProgress = true;

    // Abort conditional mediation before creating credential
    if (conditionalAbortController) {
      conditionalAbortController.abort();
      conditionalAbortController = null;
    }

    console.log('[passkey] Starting registration for', userIDHash);

    try {
      // Step 1: get registration options
      var body = new URLSearchParams({ user_id_hash: userIDHash });
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

      // Step 2: convert options
      var options = await resp.json();
      options.publicKey.challenge = base64urlToArrayBuffer(options.publicKey.challenge);
      if (options.publicKey.user && options.publicKey.user.id) {
        options.publicKey.user.id = base64urlToArrayBuffer(options.publicKey.user.id);
      }
      if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials.forEach(function (cred) {
          cred.id = base64urlToArrayBuffer(cred.id);
        });
      }

      // Step 3: browser WebAuthn API (Face ID / Touch ID prompt)
      var credential = await navigator.credentials.create({ publicKey: options.publicKey });
      console.log('[passkey] Credential created');

      // Step 4: encode and send to finish
      var attestation = encodeAttestation(credential);
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
