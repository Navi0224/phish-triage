# Interview guide: phish-triage

This guide helps you explain the project in your own words. Read the code alongside it; every
module is short. Don't memorise the answers below. Understand them, then say them your way.

---

## 1. The one-paragraph pitch

> "phish-triage is a Python tool that does the first 10 minutes of a SOC analyst's work on a reported
> phishing email. You give it an `.eml` file and it parses the headers, checks SPF/DKIM/DMARC, spots
> spoofed senders and lookalike domains, pulls out and defangs all the IOCs, hashes and inspects
> attachments, and then scores the email with transparent weighted rules. It outputs a verdict with
> every reason listed, JSON for a SIEM or SOAR, an HTML or Markdown report, and recommended response
> actions like a SOAR playbook. It never opens links or runs attachments."

---

## 2. Walkthrough of each module (in pipeline order)

### `parser.py`: raw email to structured data
- Uses Python's built-in `email` package (`BytesParser` with `policy.default`). It decodes encoded
  headers like `=?utf-8?b?...?=` and MIME parts.
- Pulls out From, Reply-To, Return-Path, To, Subject, Date, Message-ID.
- `parse_received()`: each mail server *adds its Received header on top*, so the list is newest
  first. We reverse it so the report reads like a journey: sender to your server.
- `parse_auth_results()`: reads `spf=`, `dkim=`, `dmarc=` with a regex. **Design choice:** we only
  trust the *topmost* Authentication-Results header (added by your own server), because an attacker
  can write a fake `spf=pass` header into the email they send. In production you would set
  `trusted_authserv_ids` to your mail server's name.
- `_walk_parts()`: goes through every MIME part. Text and HTML go to the bodies; anything with a
  filename is an attachment, kept as bytes in memory.
- **Defensive coding:** every header read is wrapped so malformed input gives empty values
  instead of a crash. Attackers send broken emails on purpose to break parsers.

### `iocs.py`: finding the indicators
- `_LinkParser` (built on `html.parser.HTMLParser`) walks the HTML and records each `<a href>` with
  its visible text, any `<form action>`, and password inputs. It ignores text inside `<script>`/`<style>`.
  HTMLParser only tokenises, it never executes anything.
- `extract_iocs()` collects URLs, IPs (validated with the `ipaddress` module so `999.1.1.1` is
  rejected), email addresses and domains.
- **Design choice:** URLs are taken from the plain-text body and from real `href`s, not from the
  HTML *visible text*. In a phish, the visible text is usually the genuine bank URL used as a decoy.
  If we listed it as an IOC, someone might block the real bank.
- `find_link_mismatches()`: if the link text looks like a domain and it's not the same site as the
  real `href`, that's deception. "Click here" links are skipped because they claim no destination.

### `defang.py`
- `https://evil.example/login` becomes `hxxps://evil[.]example/login`. Defanged IOCs can't be
  clicked or auto-linked in tickets, Slack or email. `refang()` reverses it for tools.

### `domains.py`: lookalike detection
- `registrable_domain()`: the part a person actually registers, e.g. `maybank2u.com.my` from
  `secure.maybank2u.com.my`. Needs special handling for two-part suffixes like `.com.my`.
- `to_unicode()`: decodes punycode (`xn--...`) so hidden Cyrillic letters show up.
- `skeleton()`: maps look-alike characters to the letters they imitate (`1`→`l`, `0`→`o`,
  Cyrillic `а`→`a`, `rn`→`m`). If two names have the same skeleton they *look* the same to a human.
- `levenshtein()`: edit distance, a classic dynamic-programming algorithm. `maybenk2u` vs
  `maybank2u` = 1.
- `check_lookalike()`: first, if the domain really belongs to a brand, stop (no false positive on
  `secure.paypal.com`). Then, for each protected brand, check in order: same name different TLD,
  homoglyph, typo-squat, brand embedded, brand as subdomain.

### `detectors/`: the rules
All detectors have the same shape: `detect_x(ctx) -> list[Finding]`. A `Finding` has a `rule_id`,
title, detail and evidence. Detectors **don't score**; they only report what they saw.
- `headers.py`: SPF/DKIM/DMARC failures, Reply-To and Return-Path mismatch, display-name spoof.
- `links.py`: lookalike domains (sender, reply-to, return-path and all URL domains), link text
  mismatch, raw-IP URLs, URL shorteners, HTML forms/password fields.
- `attachments.py`: hashes, risky extension, double extension, `MZ`/ELF header, VBA macros.
  For Office files it opens the ZIP **file list only** (no extraction), which is safe even against
  zip bombs.
- `content.py`: whole-word keyword matching for urgency, credential and payment-change phrases.
- `context.py`: the `Context` bundle passed to every detector so nothing is parsed twice.

**Why this structure?** Adding a rule is three steps: write the function, add it to
`ALL_DETECTORS`, give its `rule_id` a weight in the config. Each detector can be unit-tested alone.

### `scoring.py`
- Looks up each rule's weight from the config, sums **distinct** rules, caps at 100, applies thresholds
  (60 likely-phish, 30 suspicious).

### `playbook.py`
- Turns verdict and fired rules into response actions: block, purge, block URLs, reset credentials,
  block hashes in EDR, warn Finance for BEC, report the impersonation.
- **Design choice:** for BEC it recommends blocking the Reply-To address, not the From domain,
  because the From domain is often a real supplier being spoofed.

### `enrichment.py`
- Optional VirusTotal/URLhaus lookups. Keys come only from environment variables.
- Lookups only, never uploads (uploads to VirusTotal are visible to other subscribers).
- Every error becomes a status in the result; the triage never fails because an API is down.
- The HTTP session is passed in as a parameter, so tests use a fake session and never touch the network.

### `report.py`
- Console, JSON, Markdown, HTML.
- **Security:** the email is attacker-controlled. Every HTML value goes through `html.escape`,
  no IOC is a clickable link, and there's a Content-Security-Policy blocking scripts as a second
  layer. Markdown puts attacker values in code spans, with a fence longer than any backticks inside.
  There's a test that feeds in `<script>` and checks it comes out escaped.

### `analyzer.py` and `cli.py`
- `analyzer.py` runs the steps in order: parse, extract, detect, enrich (optional), score, recommend.
- `cli.py` is argparse: single file or folder (batch), `--json` for pipelines, `--out-dir` for reports.
  It sets the console to replace unprintable characters so Unicode tricks in subjects don't crash
  a Windows terminal.

---

## 3. Key concepts in plain English

**SPF (Sender Policy Framework).** The domain owner publishes a DNS record listing which servers may
send mail for the domain. The receiver checks the connecting server's IP against it. It checks the
*envelope* sender (Return-Path), not the From address the user sees. Results: pass, fail,
softfail (`~all`, "probably not allowed"), neutral, none.

**DKIM (DomainKeys Identified Mail).** The sending server signs the message with a private key; the
public key is in DNS. A valid signature proves the signed headers and body weren't changed and that
the signing domain (`d=`) sent it.

**DMARC.** Ties the two to the From address the user sees: DMARC passes only if SPF or DKIM passes
*and* that domain aligns with the From domain. The domain owner publishes a policy (`p=none`,
`quarantine`, `reject`) telling receivers what to do on failure. Without DMARC, an attacker could pass
SPF with their own envelope domain while showing your bank in From.

**Authentication-Results header.** Where the receiving server writes its SPF/DKIM/DMARC verdicts.
Trust only the one your own server added.

**IOC (Indicator of Compromise).** An observable artefact linked to malicious activity: URL, domain,
IP, email address, file hash. Used to block, hunt and share intelligence.

**Defanging.** Changing IOCs so they can't be clicked: `hxxp`, `[.]`, `[@]`.

**Lookalike / cousin domain, homoglyph, punycode.** Domains made to look like a trusted one.
Punycode (`xn--`) is how non-ASCII domain names are stored in DNS; a Cyrillic "а" looks identical to
a Latin "a".

**Display-name spoofing.** Putting "Maybank2u Security" as the display name on any address. Many
phone mail apps show only the name.

**BEC (Business Email Compromise).** Fraud with no malware or link: the attacker poses as a CEO or
supplier and asks for a payment or bank-detail change. Often uses a Reply-To on another domain,
a lookalike domain, or a really compromised mailbox. Usually the most expensive email threat.

**Double extension.** `invoice.pdf.exe`. Windows hides known extensions by default, so the user sees
`invoice.pdf`.

**Macros.** VBA code in Office documents (`.docm`, `.xlsm`, or old `.doc`/`.xls`), historically a
top malware delivery method. Microsoft now blocks macros in files from the internet by default, so
attackers moved to `.iso`, `.lnk`, `.html` and OneNote attachments, which is why those are in the
risky list.

**SOAR (Security Orchestration, Automation and Response).** Platforms (Splunk SOAR, Cortex XSOAR,
Microsoft Sentinel with Logic Apps...) that run **playbooks**: automated workflows like "when a
phishing report arrives: parse it, enrich IOCs, score it, if malicious purge it from all mailboxes
and block the sender, open a ticket". This project is the "parse, enrich, score, recommend" part of
such a playbook, written as a standalone tool whose JSON output a SOAR could consume.

**Hashes (MD5, SHA-1, SHA-256).** A fingerprint of a file. SHA-256 is the modern standard; MD5 and
SHA-1 are broken for collision resistance but still used as identifiers by many threat-intel feeds,
so we report all three.

---

## 4. Ten likely interview questions, with model answers

**1. Walk me through what happens when I run `phish-triage analyze email.eml`.**
"The CLI loads the config and calls the analyzer. The parser turns the file into a structured object:
headers, received chain, authentication results, bodies and attachments. The IOC module parses the
HTML for links and forms and extracts URLs, domains, IPs and emails. Then each detector looks at one
area and returns findings with evidence. If `--enrich` is set, hashes and URLs are looked up on
VirusTotal and URLhaus. The scorer adds the weights of the rules that fired and picks a verdict, the
playbook module picks response actions, and the report module prints a summary and optionally writes
JSON, Markdown or HTML."

**2. Why rule-based scoring instead of machine learning?**
"Explainability and data. In a SOC you must justify why you blocked something, and each point in my
score maps to a listed reason with evidence. ML needs a large labelled dataset I didn't have, and it's
harder to debug. Rules are also easy to tune per organisation through the config. The trade-off is
that rules miss novel attacks, so in the future I'd measure the rules on labelled data and could
add ML as one more signal rather than the only one."

**3. SPF passed but you still flagged the email. How can SPF pass on a phishing email?**
"SPF checks the envelope sender, not the From the user sees. An attacker can send from their own
domain with a perfect SPF record. And with DMARC the attacker can pass too if they use their own
lookalike domain in From. Authentication tells you the mail really came from that domain, not that
the domain is trustworthy. That's why lookalike, display-name and content checks also exist."

**4. Can an attacker fake the Authentication-Results header?**
"Yes, they can put any header in the message they send. Your receiving server adds its own
Authentication-Results at the top, so I only trust the topmost one, and you can configure the
expected authserv-id so only your server's header is accepted. Ideally the gateway also strips
incoming Authentication-Results headers that claim to be from your domain."

**5. How do you detect lookalike domains?**
"I take the registrable domain and its main label, decode punycode, and compare against each
protected brand: a homoglyph skeleton (mapping `1` to `l`, Cyrillic `а` to `a`), Levenshtein edit
distance up to 2, and checks for the brand name embedded in the domain or used as a subdomain. Real
brand domains and their subdomains are excluded first to avoid false positives. Limitations: my
suffix list is small, and short brand names cause false positives, so there's a minimum length."

**6. How do you make sure the tool itself is safe to run on malicious emails?**
"It never makes a request to any URL in the email, never writes attachments to disk, and never
executes or extracts them; just hashes them and reads header bytes and the ZIP file list.
HTML is tokenised, not rendered. The reports escape everything because the email is attacker input:
I have a test that puts a `<script>` payload in the subject and filename and checks it's escaped,
plus a CSP in the HTML report. The optional enrichment only looks up existing reports and never
uploads files."

**7. What's BEC and how does your tool handle it?**
"Business Email Compromise is fraud where the attacker impersonates a boss or supplier to get money
moved, often with no link or attachment. I check for a Reply-To on a different domain and for
payment-change wording like 'change of bank details'. The playbook tells Finance to hold the payment
and verify by phone using a number from your records, and to block the Reply-To rather than the From
domain, because that may be a real supplier. Honest limitation: BEC from a truly compromised mailbox
passes SPF/DKIM/DMARC and would only score 'suspicious' in my tool."

**8. Why does each rule count only once?**
"Fifty bad links aren't fifty times worse than one, and counting each would let one noisy rule
dominate the score. Counting once keeps the score readable: it's a sum of distinct reasons. The
evidence list still shows every instance."

**9. How would you integrate this into a real SOC / SOAR?**
"A SOAR playbook would trigger when a user reports a phish, for example via the 'Report' button
in Outlook feeding a mailbox. It would export the message as .eml, run this tool with `--json`, and
branch on the verdict: likely-phish runs containment automatically or after approval, like purging
from all mailboxes and blocking the sender and URLs; suspicious creates a ticket for an analyst;
benign auto-replies to the reporter. The JSON would also go to the SIEM so you can search for the
same IOCs across logs."

**10. What would you improve next?**
"Support Outlook `.msg` files, use the Public Suffix List and the full Unicode confusables table,
add domain age via RDAP because new domains are a strong signal, deeper attachment analysis with
oletools, and Bahasa Malaysia keyword lists for local phishing. Most importantly, I'd measure false
positive and false negative rates on a labelled dataset and tune the weights from data instead of
judgement."

Also be ready for: *"What does defanging mean?"*, *"Difference between SPF, DKIM and DMARC?"*,
*"Why MD5 if it's broken?"* (identifiers in threat-intel feeds, not security), *"How did you test
it?"* (90 pytest tests: unit tests per detector, an XSS escaping test, fake HTTP session for
enrichment, end-to-end on each sample).

---

## 5. How to demo in 2 minutes

Prepare beforehand: virtual environment activated, `pip install -e .` done, terminal font large,
`samples/` folder open.

1. **(15 s) The problem.** "SOC analysts triage reported phishing emails all day. This automates the
   first pass, like a SOAR playbook."
2. **(30 s) Batch run.** `phish-triage analyze samples/ -q`
   "Five synthetic emails: three phish variants and two benign. All five are classified correctly."
3. **(45 s) The bank phish.** `phish-triage analyze samples/01_credential_harvest_bank_lookalike.eml`
   Point at: the punycode domain that decodes to a Cyrillic "а", the link that shows
   `maybank2u.com.my` but goes elsewhere, the defanged IOCs, and that every point in the score has a
   reason. Mention the genuine bank URL is deliberately not listed as an IOC.
4. **(20 s) BEC.** `phish-triage analyze samples/03_bec_reply_to_mismatch_invoice.eml`
   Point at the Reply-To mismatch and the action "block the Reply-To, don't block the supplier's domain,
   warn Finance".
5. **(10 s) Outputs.** `phish-triage analyze samples/ -q --out-dir reports --report-format html`, open
   one HTML report. "JSON for the SIEM/SOAR, HTML for humans, everything escaped and defanged."
6. **(Close.)** "It never opens links or runs attachments, all weights are in a config file, and
   there are 90 tests including one that checks the report can't be used for XSS."

If something goes wrong in the demo, the tests are your backup: `python -m pytest -q`.
