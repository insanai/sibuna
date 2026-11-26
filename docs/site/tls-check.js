// A web page cannot read the TLS handshake of another origin. The browser makes
// the connection and the visitor copies its negotiated group from DevTools.
function httpsOrigin(input) {
  const value = input.trim();
  if (!value || /[\s\\]/u.test(value)) return null;
  const absolute = /^https:\/\//i.test(value);
  const address = absolute ? value.slice(8) : value;
  const authority = address.split(/[/?#]/u, 1)[0];
  // Only a hostname (including bracketed IPv6) and an optional numeric port.
  // Reject credentials and malformed schemes before the URL parser normalizes them.
  if (!/^(?:\[[a-f0-9:.]+\]|[^:@%\[\]]+)(?::[0-9]+)?$/iu.test(authority)) return null;
  try {
    const url = new URL(absolute ? value : 'https://' + value);
    if (url.protocol !== 'https:' || url.username || url.password) return null;
    return url.origin;
  } catch {
    return null;
  }
}

// The three ECDHE-MLKEM groups defined in RFC 10024. Other group names
// remain inconclusive until the checker recognizes them explicitly.
function outcome(group) {
  if (/^(X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024)$/i.test(group)) return 'hybrid';
  // Older TLS versions can display the exchange and curve together in DevTools.
  const curve = group.replace(/^ECDHE_(RSA|ECDSA) with /i, '');
  if (/^(X25519|X448|P-(256|384|521)|secp(256|384|521)r1|prime256v1|ffdhe(2048|3072|4096|6144|8192))$/i.test(curve)) {
    return 'classical';
  }
  return 'unknown';
}

const widget = document.querySelector('[data-tls-check]');
const target = widget.querySelector('#tls-url');
const error = widget.querySelector('#tls-url-error');
const observation = widget.querySelector('#tls-observation');
const originLink = widget.querySelector('#tls-origin');
const group = widget.querySelector('#tls-group');
const results = widget.querySelectorAll('[data-outcome]');

function showResult(kind) {
  for (const result of results) result.hidden = result.dataset.outcome !== kind;
}

function clearObservation() {
  observation.hidden = true;
  originLink.removeAttribute('href');
  originLink.textContent = '';
  group.value = '';
  showResult(null);
  error.hidden = true;
  target.removeAttribute('aria-invalid');
}

target.addEventListener('input', clearObservation);
widget.querySelector('#tls-target-form').addEventListener('submit', event => {
  event.preventDefault();
  clearObservation();
  const origin = httpsOrigin(target.value);
  if (!origin) {
    error.hidden = false;
    target.setAttribute('aria-invalid', 'true');
    target.focus();
    return;
  }
  originLink.href = origin;
  originLink.textContent = origin;
  observation.hidden = false;
  originLink.click();
});

group.addEventListener('input', event => {
  showResult(event.inputType === 'insertFromPaste' ? outcome(group.value.trim()) : null);
});
widget.querySelector('#tls-group-form').addEventListener('submit', event => {
  event.preventDefault();
  showResult(outcome(group.value.trim()));
});
widget.hidden = false;
