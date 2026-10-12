// detect.js — find personal and secret data in text.
//
// Plain script (no modules) so index.html works when opened straight from disk, and a
// CommonJS export so the tests can run in Node.
//
// THE DESIGN RULE: this file never makes a network call, and nothing in this project does.
// A redaction tool that uploads your document to a server to redact it is an oxymoron — you
// have handed the sensitive data to one more party in order to hide it. All detection is local.
//
// The second rule is about false positives. A detector that flags every 16-digit number as a
// card teaches people to ignore it, and then real cards go out. So anything with a checksum
// gets validated: card numbers via Luhn, IBANs via mod-97. Unvalidated guesses are reported
// separately as "possible", never mixed in with the certain ones.

;(function (root) {

  // ── checksum validators ────────────────────────────────────────────────────

  function luhn(digits) {
    let sum = 0, alt = false
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = Number(digits[i])
      if (alt) { n *= 2; if (n > 9) n -= 9 }
      sum += n
      alt = !alt
    }
    return digits.length >= 13 && sum % 10 === 0
  }

  function ibanValid(raw) {
    const s = raw.replace(/[\s-]/g, '').toUpperCase()
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false
    const moved = s.slice(4) + s.slice(0, 4)
    const expanded = moved.replace(/[A-Z]/g, (c) => c.charCodeAt(0) - 55)
    // mod-97 on a long numeric string, in chunks to stay inside Number precision
    let remainder = 0
    for (const ch of expanded) remainder = (remainder * 10 + Number(ch)) % 97
    return remainder === 1
  }

  // ── detectors ──────────────────────────────────────────────────────────────
  // confidence: 'certain'  — structurally unambiguous or checksum-validated
  //             'likely'   — strong pattern, small chance of a false positive
  //             'possible' — heuristic; shown separately, never auto-redacted silently

  const DETECTORS = [
    { type: 'email', label: 'Email address', confidence: 'certain',
      re: /\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/g },

    { type: 'card', label: 'Payment card', confidence: 'certain',
      re: /\b(?:\d[ -]?){13,19}\b/g,
      validate: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d) } },

    { type: 'iban', label: 'IBAN', confidence: 'certain',
      re: /\b[A-Z]{2}\d{2}[\sA-Z0-9]{11,32}\b/g, validate: ibanValid },

    { type: 'ssn', label: 'US SSN', confidence: 'likely',
      re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },

    { type: 'nin', label: 'NIN / BVN (11 digits)', confidence: 'possible',
      re: /\b\d{11}\b/g },

    { type: 'phone', label: 'Phone number', confidence: 'likely',
      re: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{0,4}/g,
      validate: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 10 && d.length <= 15 } },

    { type: 'apikey', label: 'API key / token', confidence: 'certain',
      re: /\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|pit-[a-f0-9-]{20,})\b/g },

    { type: 'jwt', label: 'JWT', confidence: 'certain',
      re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },

    { type: 'ipv4', label: 'IP address', confidence: 'likely',
      re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },

    { type: 'dob', label: 'Date of birth', confidence: 'possible',
      re: /\b(?:0?[1-9]|[12]\d|3[01])[\/.-](?:0?[1-9]|1[0-2])[\/.-](?:19|20)\d{2}\b/g },

    { type: 'postcode', label: 'UK postcode', confidence: 'likely',
      re: /\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b/g },

    { type: 'name', label: 'Possible name', confidence: 'possible',
      re: /(?:\b(?:Dear|Hi|Hello|Regards|Sincerely|From|To|Attn|Mr\.?|Mrs\.?|Ms\.?|Dr\.?)\s+)([A-Z][a-z]{1,15}(?:\s+[A-Z][a-z]{1,15}){0,2})/g,
      group: 1 },
  ]

  const ORDER = { certain: 0, likely: 1, possible: 2 }

  /** @returns {{findings:Array, byType:Object}} */
  function detect(text) {
    const findings = []

    for (const d of DETECTORS) {
      d.re.lastIndex = 0
      let m
      while ((m = d.re.exec(text)) !== null) {
        const value = d.group ? m[d.group] : m[0]
        if (!value || !value.trim()) continue
        const start = d.group ? m.index + m[0].indexOf(value) : m.index
        if (d.validate && !d.validate(value)) continue
        findings.push({
          type: d.type, label: d.label, confidence: d.confidence,
          value: value.trim(), start, end: start + value.trim().length,
        })
        if (m.index === d.re.lastIndex) d.re.lastIndex++   // guard zero-length matches
      }
    }

    // Overlaps happen constantly — a card number also looks like a phone number, an email
    // contains something phone-shaped. Keep the most confident match for any given span.
    findings.sort((a, b) =>
      a.start - b.start ||
      ORDER[a.confidence] - ORDER[b.confidence] ||
      (b.end - b.start) - (a.end - a.start))

    const kept = []
    for (const f of findings) {
      if (kept.some((k) => f.start < k.end && k.start < f.end)) continue
      kept.push(f)
    }

    const byType = {}
    for (const f of kept) (byType[f.type] ||= []).push(f)
    return { findings: kept, byType }
  }

  /**
   * @param {string} mode  'mask' | 'label' | 'remove'
   * @param {string[]} types  which types to redact
   */
  function redact(text, findings, mode = 'label', types = null) {
    const active = findings
      .filter((f) => !types || types.includes(f.type))
      .sort((a, b) => b.start - a.start)   // back to front, so offsets stay valid

    let out = text
    for (const f of active) {
      let replacement
      if (mode === 'mask') {
        // keep the shape so the document still reads naturally
        replacement = f.value.replace(/[A-Za-z0-9]/g, '•')
      } else if (mode === 'remove') {
        replacement = ''
      } else {
        replacement = `[${f.type.toUpperCase()}]`
      }
      out = out.slice(0, f.start) + replacement + out.slice(f.end)
    }
    return out
  }

  const api = { detect, redact, DETECTORS, _luhn: luhn, _ibanValid: ibanValid }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  if (typeof window !== 'undefined') window.PII = api

})(this)
