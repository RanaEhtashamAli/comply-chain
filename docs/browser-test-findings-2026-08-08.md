# ComplyChain — Manual Browser Test Findings

**Date:** 2026-08-08
**Target:** https://complychain.dev against https://api.complychain.dev (deployed)
**Method:** Manual agent-driven browser session. Every page and feature exercised through the UI.
Root causes traced into source and verified independently; downloaded artifacts opened and inspected.

---

## Fix status (2026-08-08)

All findings except L5 and L6 are fixed in commits `e2b28ce` (backend) and
`56cc15e` (frontend). The Python suite passes 920/920 and the frontend
typechecks and builds. Each fix was verified by exercising the behaviour, not by
inspection alone.

Two corrections to this report, found while fixing:

- **H2 was half wrong.** The audit-chain gap was *not* "the API skips what the
  CLI does" — the CLI's `scan` command does not log to the audit chain either.
  `log_transaction()` was only ever called by the data-disposal,
  vendor-management and change-management modules, so scanning was never wired
  to the audit log at all. The assessment-persistence half of H2 was correct.
- **A further bug (H4) was found underneath it**, which had been making the
  audit chain unwritable regardless. See below.

Not fixed, and why:

- **L5** (recommendations written for CLI operators) — a content rewrite across
  five regulation modules, and a judgement call about audience rather than a
  defect. Worth doing, but it is its own piece of work.
- **L6** (sanctions "fallback" vs. scan "verified") — not root-caused during
  testing, so there is nothing yet to fix with confidence. It needs
  investigation first.

**Deployed and re-verified.** After deployment:

- `/key-rotation/check` returns `ok: true` with a keystore present — the exact
  state that used to produce a 500 (H1 confirmed fixed in production).
- `/regulations/assess` returns 200. It had also been 500ing, because
  `pci_dss.py:106`, `soc2.py:163` and `hipaa.py:114` all call
  `KeyVerifier().verify()` — so H1 broke the Assessment page as well as the Keys
  page. The original report understated its blast radius.
- The audit chain is live and verifying: 46 entries, `ok: true` (H2/H4 confirmed).
- **Playwright: 166 passed, 0 failed, 0 flaky** across chromium, firefox, webkit,
  mobile and the destructive project. Python: 920 passed.

One new finding (M9) surfaced during that re-verification, and one durability
observation is recorded at the end.

---

## Summary

18 findings. Three were serious enough to block a demo; one of them was caused
*by* this test session (H1).

| # | Severity | Area | Finding |
|---|----------|------|---------|
| H1 | High | Keys | Generating a key permanently breaks the Keys page (500) |
| H2 | High | API | REST API skips the persistence the CLI performs — three UI features can never show data |
| H3 | High | Monitoring | A rejected job is still registered and later persisted |
| H4 | High | Audit | Auditor wrote the chain to a different directory than the readers read |
| M1 | Medium | Crypto | Quantum-safe crypto silently falls back to RSA-4096; benchmark mislabels it |
| M2 | Medium | SAR | Subject information is always "Unknown" — the SAR is not filable |
| M3 | Medium | SAR | XML `TotalAmount` attribute is always `0` |
| M4 | Medium | Explainability | Advises filing a CTR for a wire transfer, contradicting its own verdict |
| M5 | Medium | Rules | Validator vocabulary rejects valid fields and can pass broken rules |
| M6 | Medium | Frontend | Blob downloads swallow the server's error message (4 sites) |
| M7 | Medium | Frontend | One failed request hides another's successful data on the Keys page |
| M8 | Medium | API | Unhandled 500s reach the browser as opaque CORS errors |
| L1 | Low | Routing | No catch-all route — unknown URLs render a blank pane |
| L2 | Low | Layout | 5 of 6 pages overflow horizontally on mobile |
| L3 | Low | Audit | An uninitialised chain is reported as "broken" |
| L4 | Low | Assessment | Risk scores rendered as raw unformatted floats |
| L5 | Low | Assessment | Recommendations tell browser users to set env vars and run CLI commands |
| L6 | Low | Sanctions | Cache reports "fallback" while scans report sanctions "verified" |

---

## High

### H1 — Generating a key permanently breaks the Keys page

**Reproduce:** Keys → Danger zone → Generate new key → confirm. Reload.

The generation itself succeeds: `/key-rotation/history` gains an `RSA-4096` entry with a
signed chain-of-custody manifest, and `/keys/public` returns 200. But
`GET /key-rotation/check` now returns **HTTP 500** on every request, and the Keys page
renders only "Could not load key status" — no status badge, no algorithm, no age, no
public-key link, and no rotation history.

**Root cause:**
- `complychain/key_management/rotation.py:203` writes `created_at` timezone-aware:
  `datetime.now(tz=timezone.utc).isoformat()`
- `complychain/verification/key_verifier.py:75` computes age as
  `datetime.utcnow() - datetime.fromisoformat(created_at)` — **naive minus aware → `TypeError`**
- The enclosing `except` catches only `(json.JSONDecodeError, KeyError, ValueError)`, so the
  `TypeError` escapes and becomes an unhandled 500

Before generation there was no `keystore.json`, so that branch was skipped and `/check`
worked. Creating a key is what triggers it.

**Note:** this is currently ACTIVE on the deployment. Either fix the comparison or delete
`keystore.json` from the key directory to restore the page.

**Fix:** make both sides timezone-aware (or both naive) and add `TypeError` to the caught
exceptions.

### H2 — The REST API skips the persistence the CLI performs

Three separate UI features are permanently empty because the API endpoints compute and
return results without writing them anywhere. Only the CLI and the monitoring scheduler persist.

| UI feature | Endpoint | Missing side-effect |
|---|---|---|
| Assessment → History (30 days) | `POST /regulations/assess` | never calls `AssessmentStore.save()` |
| Assessment → Diff vs. previous | same | same — `/diff` returns 404 |
| Audit → Chain status / entries | `POST /scan` | never writes an audit-chain entry |

`store.save()` is called only from `cli.py:755` and `monitoring/scheduler.py:172`;
`registry.assess_all()` does not persist. `api/routes/scan.py` calls `GLBAScanner().scan()`
and returns — it never constructs a `GLBAAuditor`.

**Observed:** ran an assessment, expanded the GLBA card immediately — "No prior assessments."
and "No previous assessment to compare against." Ran a scan, opened Audit — `total_entries: 0`,
`audit_chain.json not found`.

The features look functional and are not. For a compliance product the audit-chain gap is
the more serious half: a Merkle-chained audit log that never records anything scanned
through the product's own UI.

### H3 — A rejected monitoring job is still registered and persisted

**Reproduce:** Monitoring → set cron `99 99 * * *` → Create. The UI correctly shows
`Invalid schedule: ... the last value (99) is higher than the maximum value (23)`.
Now create a *valid* job. The rejected job appears in the table alongside it, with a real
`job_id`, and survives a reload.

**Root cause:** `complychain/monitoring/scheduler.py:66` inserts the job into `self._jobs`
*before* line 69 calls `_add_apscheduler_job()`, which is what raises on a bad cron. The API
converts the exception to a 400 but never removes the orphan. The next successful create
calls `_persist(scheduler)`, which serialises `self._jobs` — orphan included — to disk.

The orphan will never fire (APScheduler never accepted it) but looks live in the UI.

**Fix:** only insert into `self._jobs` after `_add_apscheduler_job()` succeeds, or roll back
in an `except`.

### H4 — The auditor wrote the chain where nothing reads it

Found while fixing H2, and the reason the audit chain could never have worked.

`audit_system.py` resolved its default directory as:

```python
default_dir = Path(os.environ.get('COMPLYCHAIN_AUDIT_DIR', '')) or Path.home() / '.complychain' / 'audit'
```

`Path('')` is `Path('.')`, which is **truthy**, so the `or` fallback never fired.
With the environment variable unset, `GLBAAuditor` wrote `audit_chain.json` into the
process's *current working directory*, while `AuditChainVerifier` and
`GET /audit/chain` — both of which use `os.environ.get(key, default)` correctly —
read `~/.complychain/audit`. Writer and reader never agreed.

This also explains the stray `audit_chain.json` sitting in the repository root: it
was written by a process whose working directory was the repo.

**Fix:** resolve the environment variable explicitly, treating empty as unset, so all
three agree.

---

## Medium

### M1 — Quantum-safe crypto silently falls back to RSA-4096

Benchmark with `dilithium3` selected returned **key generation 408.335 ms / signing 184.131 ms**.
Those are RSA-4096 timings; Dilithium3 signing is sub-millisecond and its keygen is
~0.05 ms. The rotation-history entry independently confirms it: `"new_algorithm":"RSA-4096"`.

So the deployment is not running ML-DSA-65 / FIPS 204 — the product's headline claim — and
the Benchmark panel attributes RSA numbers to the algorithm the user picked, with no
indication a fallback occurred. The `/benchmark` response contains no field reporting which
algorithm actually ran.

**Fix:** return the effective algorithm in the response and surface it in the UI; warn when
the requested algorithm is unavailable.

### M2 — SAR subject information is always "Unknown"

A SAR generated from a scan of `{"sender": "acct-nw-001", "receiver": "acct-offshore-914", ...}`
produced:

```xml
<SubjectInformation>
  <BeneficiaryName>Unknown</BeneficiaryName>
  <OriginatorName>Unknown</OriginatorName>
  <AccountNumber>Unknown</AccountNumber>
  <TaxIDNumber>Unknown</TaxIDNumber>
  <Address>Unknown</Address>
</SubjectInformation>
```

`sar_generator.py:310-314` reads `beneficiary`, `originator`, `account_number`, `tax_id`,
`address` — but the Scanner's own placeholder tells users to supply `sender` and `receiver`,
and nothing maps between them. Every SAR generated through the UI has an empty subject
section, which is the part a BSA officer most needs.

**Fix:** map `sender`→originator and `receiver`→beneficiary, or change the Scanner
placeholder and document the fields the SAR generator expects.

### M3 — SAR XML `TotalAmount` is always 0

```xml
<EFilingBatchXML xmlns="FinCEN/BSAEFILING" SeqNum="1" TotalAmount="0">
  ...
  <TransactionInformation><Amount>87500</Amount>
```

`sar_generator.py:96` reads `transaction_summary.get("amount", 0)`, but the summary is keyed
`"Amount"` (capitalised) — as the `<Amount>` element it generates proves. The batch-level
total in a FinCEN e-filing document is therefore always zero.

### M4 — Explainability gives wrong regulatory advice for wire transfers

For an $87,500 **wire**, the scanner correctly returned `"ctr_required": false` — CTRs apply
to currency (cash) transactions. But the explanation attached to the same result says:

> "A transaction of $87,500.00 was processed, exceeding the $10,000 Currency Transaction
> Report (CTR) threshold established under 31 U.S.C. § 5313."

and the remediation says *"Ensure a Currency Transaction Report (CTR) is filed with FinCEN
within 15 days."* That advice is incorrect for a wire, and it contradicts the scanner's own
verdict in the same payload. The `HIGH_VALUE_TRANSACTION` explanation hardcodes CTR language
without checking whether the transaction is cash.

The scanner logic is right; the explanation layer is wrong.

### M5 — Rule validator vocabulary is wrong in both directions

Validating a rule with condition `is_cross_border and is_wire_transfer` returns:

> Rule 'cross_border_wire': invalid condition — 'is_cross_border' is not defined

`rules/engine.py:135-138` validates against a hardcoded six-field dummy — `amount`,
`transaction_type`, `beneficiary`, `originator`, `currency`, `destination_country` — which
does not match the transaction schema the scanner and ML feature extractor accept
(`is_high_value`, `is_cross_border`, `is_wire_transfer`, `is_new_recipient`, `is_after_hours`,
`account_age_days`, and more). Legitimate rules are rejected.

Conversely, line 153's `except Exception: pass` swallows every error that isn't an
`InvalidExpression`, so genuinely broken conditions can pass validation.

### M6 — Blob downloads swallow the server's error message

`getApiErrorMessage()` reads `err.response?.data?.detail`, but four call sites use
`responseType: "blob"`, so axios never parses an error body as JSON and `detail` is always
`undefined`. Every failure on these paths shows the generic fallback instead of the reason:

- `AuditPage.tsx:31` — compliance report
- `AuditPage.tsx:86` — evidence export
- `KeysPage.tsx:20` — sign a file
- `ScannerPage.tsx:78` — SAR generation

**Fix:** on error, read the Blob back as text and `JSON.parse` it before falling back.

### M7 — One failed request hides another's successful data

`KeysPage.refresh()` awaits `Promise.all([/key-rotation/check, /key-rotation/history])` and
sets both states only after both resolve. When `/check` 500s (see H1), the history response —
which returns 200 with real data — is discarded, and the page shows nothing rather than the
history it successfully fetched.

**Fix:** `Promise.allSettled`, or independent state per request.

### M8 — Unhandled 500s reach the browser as CORS errors

The browser reported:

> Access to XMLHttpRequest at 'https://api.complychain.dev/key-rotation/check' has been
> blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present

The endpoint was actually returning a 500. Starlette's error response bypasses
`CORSMiddleware`, so unhandled exceptions lose their CORS headers and surface as a CORS
failure — pointing debugging at the wrong subsystem entirely.

**Fix:** add an exception handler that returns a JSON 500 through the normal middleware
stack.

---

## Low / UX

### L1 — No catch-all route
`App.tsx` declares no fallback `<Route>`. `/definitely-not-a-route` renders the sidebar with
a completely empty content pane — no 404, no redirect.

### L2 — Mobile layout overflows on 5 of 6 pages
At 390×844 the sidebar is a fixed `w-56` (224px — 57% of the viewport) and the Assessment and
Monitoring forms are `grid-cols-2` with no breakpoints.

| Route | Overflow |
|---|---|
| /admin | 310 px |
| /keys | 196 px |
| /audit | 193 px |
| /assessment | 154 px |
| /monitor | 154 px |
| /scanner | 0 px |

### L3 — An uninitialised audit chain is reported as "broken"
A fresh deployment with no `audit_chain.json` shows a red **"Chain broken or unverifiable"**
badge. "Not yet initialised" and "tampered with" are very different states for a compliance
product to conflate, and the alarming one is shown by default.

### L4 — Risk scores rendered as raw floats
`Risk score: 0.552`, `0.9167`, `0.9444`, `0.8571`, and `1`. Inconsistent precision, no
percentage or scale. (The Scanner's own risk score uses a 0–100 scale — so the two pages
disagree on units too.)

### L5 — Recommendations are not actionable from a browser
Assessment recommendations instruct the user to `Set COMPLYCHAIN_TLS_ENABLED=true`,
`Set COMPLYCHAIN_VENDOR_DIR`, and run `complychain train-model <data.json>` — none of which a
web-dashboard user can do. The recommendation text is written for CLI operators.

### L6 — Sanctions status inconsistency
Admin reports `Cache status: fallback`, while a scan on the same deployment returned
`"sanctions_data_verified": true, "sanctions_status": "verified"`. Not root-caused; worth
confirming whether a scan can legitimately report "verified" while the cache is on fallback
data, since sanctions screening accuracy is the point of the feature.

---

## Found after the fixes (not yet fixed)

### M9 — `sign=true` can silently produce an unsigned evidence package

`EvidencePackage._sign_manifest()` (`complychain/export/evidence.py:152`) wraps its
whole body in `try/except Exception: pass` and returns `None` on any failure —
including the ordinary case where no institutional key exists yet. The export then
succeeds, the manifest carries `"signature": null`, and nothing tells the caller
that the signing they explicitly asked for did not happen. The UI's "Sign manifest"
box stays checked throughout.

Observed directly: with no key on the deployment, exporting with signing enabled
produced a manifest with a null signature and no error. Once a key existed, signing
worked.

For a package whose purpose is to be handed to an auditor, "unsigned but looks
signed" is the wrong failure mode. It should either fail loudly, or report
`"signed": false` with the reason so the UI can say so.

### Durability observation

State does not appear to be uniformly persistent. The audit chain survives
comfortably (46 entries, stable across repeated reads and multi-minute gaps), but
the institutional key and rotation history created by one test run had vanished by
the time I checked minutes later — while a key generated afterwards persisted fine
for 120s+. That pattern is consistent with a container restart wiping paths that
are not on the mounted volume, with the audit directory being on it and the key
directory not.

I could not inspect the Railway volume configuration, so this is an observation
rather than a diagnosis. Worth confirming the volume covers the key directory and
the assessment store, not just the audit directory — a signing key that disappears
on restart takes the verifiability of every signature with it.

## What works well

Verified working, not merely rendered:

- **Evidence package** — exported ZIP contains 8 members plus a signed `manifest.json`; every
  SHA-256 hash in the manifest recomputed and matched its member. This is the best-built
  feature in the product.
- **Sign / verify round trip** — signed a file through the UI, downloaded the `.sig`, verified
  it back to "Valid signature"; a tampered copy of the same file correctly returned
  "Invalid signature".
- **Compliance reports** — daily/monthly/incident all download real PDFs (`%PDF-1.3`).
- **SAR generation** — all three formats produce genuine artifacts: valid `%PDF-1.4`,
  well-formed FinCEN `EFilingBatchXML`, parseable JSON. (Content defects are M2/M3.)
- **Scan + explain** — high-quality output: ranked contributing factors with weights,
  evidence, per-factor remediation, and a readable narrative.
- **Cron validation** — rejected both a malformed expression and a structurally valid but
  out-of-range one (`99 99 * * *`), with clear messages.
- **Monitoring persistence** — a created job survives a reload; Stop removes it cleanly.
- **Train model** — trained on a 12-row fixture, returned correct metrics
  (`training_samples: 12`, `anomaly_ratio: 0.1667` = 2/12) and an isolated model path.
- **SPA routing** — all six routes load correctly on direct navigation (nginx fallback works).
- **API key gate** — persists across reload; a bad key is cleared on 401 and returns the gate.

---

## Test session side-effects on the deployment

- **The Keys page is currently broken** (H1) and will stay broken until `keystore.json` is
  removed or the datetime bug is fixed.
- An institutional RSA-4096 signing key now exists where none did before.
- One `models/trained_20260808_021657_682993` directory was written.
- Assessment and scan calls were made; neither persists anything (H2), so no data accumulated.
- Both monitoring jobs created during testing were stopped; `GET /monitor` returns `[]`.
