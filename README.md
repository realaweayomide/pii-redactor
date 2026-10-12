# PII Redactor

Finds emails, payment cards, IBANs, API keys, national IDs, IP addresses and more in text — then
redacts them, in whichever style you need.

**[▶ Live demo](https://realaweayomide.github.io/pii-redactor/)** · built by [Ayomide Awe](https://github.com/realaweayomide)

## Nothing is uploaded. Ever.

All detection and redaction happens in the page, in your browser. There is no server, no API and
no network request — **disconnect your internet and it still works.**

That isn't a feature, it's the entire premise. A redaction tool that sends your document to a
server in order to redact it is an oxymoron: you've handed the sensitive data to one more party
in order to hide it. Any tool asking you to upload a document to remove its PII has already
failed at the job.

## The hard part is false positives, not detection

Finding something that looks like a card number is easy. The problem is that a tool which flags
every 16-digit number teaches people to ignore it — and then a real card goes out in an email.

So anything with a checksum gets **validated**, not pattern-matched:

| Type | How it's confirmed |
|---|---|
| Payment cards | **Luhn algorithm** — `4111 1111 1111 1111` is flagged; `1234 5678 1234 5678` is not |
| IBANs | **mod-97 checksum** — a tampered digit is rejected |
| SSNs | structural rules (no `000`, `666`, or `9xx` prefixes) |
| Phone numbers | digit-count bounds after stripping punctuation |

Everything else is labelled by confidence — **certain**, **likely** or **possible** — and shown
separately. Heuristic guesses (an 11-digit number that *might* be a NIN, a capitalised word after
"Dear" that *might* be a name) are never quietly mixed in with the things it's sure about.

## Overlaps are resolved, not duplicated

A card number also matches the phone pattern. An email contains something phone-shaped. Rather
than reporting both, findings are sorted by confidence and span, and overlapping matches are
dropped — so you get one finding per piece of data, at the highest confidence available.

## Three redaction styles

| Style | Output | Use when |
|---|---|---|
| **Label** | `[EMAIL]` | sharing a document and the reader needs to know what was removed |
| **Mask** | `•••••` | keeping the visual shape so the page still reads naturally |
| **Remove** | *(deleted)* | the data shouldn't leave a trace at all |

Toggle individual types on and off — redact the API keys from a log while leaving the customer
names intact, or the reverse.

## Run it

Open `index.html`. No install, no build, no dependencies.

```bash
npm test     # 21 tests: checksums, detection, overlap handling, redaction offsets
```

The redaction tests matter more than they look: replacements are applied **back to front**, so
that replacing one match doesn't invalidate the character offsets of the next one. Front-to-back
corrupts the output as soon as a replacement differs in length from the original.

## Limits — worth being honest about

- **Names and addresses are genuinely hard.** It only catches names in obvious positions (after
  "Dear", "Regards", a title). Free-standing names in prose will be missed. Treat this as a first
  pass, not a compliance guarantee.
- **No OCR and no file parsing.** It works on text you paste.
- **It does not know your context.** A number that's innocuous in one document is sensitive in
  another. Review the findings; don't trust the tool blindly.

## License

MIT
