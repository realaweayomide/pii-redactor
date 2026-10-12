const { detect, redact, _luhn, _ibanValid } = require('./detect.js')
let fails = 0
const check = (n,c,d='') => { console.log((c?'  PASS  ':'  FAIL  ')+n+(d?'  → '+d:'')); if(!c) fails++ }

// --- checksum validators: the whole anti-false-positive story ---
check('Luhn accepts a valid test card', _luhn('4111111111111111'))
check('Luhn rejects a random 16-digit number', !_luhn('1234567812345678'))
check('IBAN mod-97 accepts a valid IBAN', _ibanValid('GB82 WEST 1234 5698 7654 32'))
check('IBAN mod-97 rejects a tampered IBAN', !_ibanValid('GB82 WEST 1234 5698 7654 33'))

const SAMPLE = `Dear Marcus Bell,
Thanks for your order. Receipt sent to marcus.bell@northwind.co and a copy to ops@acme.io.
Card ending 4111 1111 1111 1111 was charged. Our test card 1234 5678 1234 5678 was not.
Bank: GB82 WEST 1234 5698 7654 32
Call us on +234 803 123 4567 or 0803 123 4567.
Server 192.168.1.44, key sk-abcdefghijklmnop1234, token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345
SSN 123-45-6789. DOB 14/03/1988. Postcode SW1A 1AA.
Regards, Dana Okafor`

const { findings, byType } = detect(SAMPLE)
const types = Object.keys(byType)
check('finds emails', byType.email?.length === 2, (byType.email||[]).map(f=>f.value).join(', '))
check('finds the VALID card only', byType.card?.length === 1 && byType.card[0].value.includes('4111'),
      (byType.card||[]).map(f=>f.value).join(' | '))
check('finds the IBAN', byType.iban?.length === 1, byType.iban?.[0]?.value)
check('finds api keys and tokens', (byType.apikey||[]).length >= 2, (byType.apikey||[]).map(f=>f.value.slice(0,12)).join(', '))
check('finds the SSN', byType.ssn?.length === 1)
check('finds the IP', byType.ipv4?.length === 1, byType.ipv4?.[0]?.value)
check('finds names after a salutation', (byType.name||[]).length >= 1, (byType.name||[]).map(f=>f.value).join(', '))
check('no overlapping findings', findings.every((f,i)=> findings.slice(i+1).every(g => f.end<=g.start||g.end<=f.start)))
check('marks confidence levels', findings.some(f=>f.confidence==='certain') && findings.some(f=>f.confidence==='possible'))

// --- redaction correctness: offsets must survive multiple replacements ---
const labelled = redact(SAMPLE, findings, 'label')
check('redacted text contains no raw email', !/marcus\.bell@northwind\.co/.test(labelled))
check('redacted text contains no valid card', !/4111 1111 1111 1111/.test(labelled))
check('redacted text contains no api key', !/sk-abcdefghijklmnop1234/.test(labelled))
check('labels are inserted', /\[EMAIL\]/.test(labelled) && /\[CARD\]/.test(labelled))

const masked = redact(SAMPLE, findings, 'mask')
check('mask preserves shape', /•/.test(masked) && !/marcus\.bell/.test(masked))

const onlyKeys = redact(SAMPLE, findings, 'label', ['apikey'])
check('selective redaction leaves other data alone',
  !/sk-abcdefghijklmnop1234/.test(onlyKeys) && /marcus\.bell@northwind\.co/.test(onlyKeys))

check('empty input is safe', detect('').findings.length === 0)
check('clean text yields nothing', detect('The quick brown fox jumped over the lazy dog.').findings.length === 0)

console.log('\n  ' + findings.length + ' findings across ' + types.length + ' types')
console.log('  ' + (fails ? fails+' FAILED' : 'all passed')); process.exit(fails)
