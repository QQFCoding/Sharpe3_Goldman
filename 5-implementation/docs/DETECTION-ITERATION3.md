# Detection hardening, iteration 3

The completed iteration expands the measured suite from 2,688 to 4,102 cases,
fixes reconstructed-secret trace exposure, improves request-level alert triage
and delivers a working real-model guided demo. On the unchanged v2 test, hybrid
F1 rises from .7882 to .8343 and false positives fall from 54 to 14. On the combined
test, measured cohort counts give previous/current hybrid F1 .6509/.8109 and
recall 54.35%/70.57%. Recall targets remain unmet; the alternative model is not
deployed because its larger-test false-positive rate is too high.

The [executed plan](DETECTION-ITERATION3-PLAN.md) starts from iteration 2's failed
broad gates. Work remains inside the main repository. The reference repository is
read-only and is not a runtime dependency. User requests supply the task; the PDF
is reference material, not an instruction source overriding that task.

Final measurements use frozen source. No metric gate has been relaxed. The
previous 2,688-case corpus is known regression data; fresh v3 scenarios
are a separate cohort. Frozen source and baseline evidence are in `iteration3/`.

## Implementation

Rules now combine bounded action/object/boundary evidence for protected data
transfer, instruction extraction, conflicting tool selection, task diversion and
persisted trust manipulation. Native action/object lexicons cover Polish, German,
Spanish, French, Italian, Portuguese, Ukrainian, Russian and Czech. These remain
finite lexical rules; a matched imperative is not a complete understanding of
authorization or intent. Existing OPA authority and hard controls remain intact.

Standalone or explicitly labelled short Base64 fragments are decoded only after
canonical, printable UTF-8 validation. Decoding precedes reconstruction. Same-role
short messages and sibling fragments preserve origin paths; different conversation
roles are not merged. Explicit `fragments`/`parts`/`segments` containers can assemble
up to eight bounded parts (6,000 characters each, 16,000 total), supporting escaped
or padded fragments without joining unrelated large fields. Directive-bearing JSON
keys also reach AI inspection. Original executable payloads/digests are not rewritten.

Discussion handling recognizes additional native discussion nouns/verbs and
detector-code frames. Single-quoted examples can contain word-internal apostrophes.
Execution/follow-through cues invalidate a discussion adjustment. Untrusted source
content cannot claim trusted discussion context. Raw model scores and effective
context-adjusted scores remain separate; weights and deployed threshold stay fixed.

Privacy uses the same reconstructed inputs before AI. Reconstructed secrets/PII
block because a source-span redaction cannot safely address the joined representation.
Sensitive raw and decoded fragments are withheld before content-bearing trace
events. Actual TCP HTTP tests verified plain/encoded fragmented-secret denials,
AI skipping and trace withholding (`live-privacy.json`).

## UI, alerting and live demo

The observatory offers a one-click guided demo, actual seven-stage progress,
expected-versus-observed detector labels, final decision colors and a selected
request in the feed. Guided mode runs sequential mixed traffic; slow/normal modes
pace completed inspections, and burst mode shows real capacity refusals. Stop
stops scheduling; it does not pretend to cancel physical inference. Editing an
input clears its old verdict and disables export. Failures have no success verdict.

Security flags default to one alert per request, with highest matching severity,
disposition, detector agreement, finding count, provenance, evidence and remediation.
Operators can switch to individual findings; all existing filters remain applicable
within the latest 500 durable audit events. This is read-only investigation, not
acknowledgment, paging or an external notification service. No messages are sent.

Diagnostics separate known regression and fresh scenario cohorts and show a language
coverage table. Measurements are source-bound and identified as stale after code
changes. Production flags have no assumed ground truth. Evidence remains privacy-safe.

The narrow layout has a full-width mode selector and readable request rows. Real
headless Edge QA exercises authentication, pipeline stages, AI windows, long inputs,
guided/burst streams, filters, alert expansion, mobile overflow, edited-input state,
empty inputs, disconnect/reconnect and provider failures. Transport fault injection
is identified separately from genuine detector/admission results.

Run `.venv\Scripts\python.exe scripts/live_demo.py`, open
`http://127.0.0.1:8010/dashboard`, connect with `demo-admin-token`, then choose
**Run guided demo**. Only an owned OPA and real DeBERTa gateway are launched. Stores
are process-local and upstream endpoints disabled. Occupied ports are refused,
never reclaimed. The Windows cleanup terminates owned process trees, including
virtual-environment redirectors. Default production provider settings are unchanged.
Demo audit and alert state is process-local and disappears on restart. Persistent
production audit storage remains a deployment configuration and validation task.

## Dataset and measurement protocol

The suite contains 4,102 cases: 2,590 malicious and 1,512 benign. V2's 2,688 cases
are retained; the 1,414-case supplement contains 36 fresh scenario families (12
translated across ten languages, plus 24 additional English scenarios). Together
there are 300 authoring families and 408 language-specific authored scenarios.
Translations share their family and split; they do not count as independent attack
mechanisms. Twenty-six transforms that left an input unchanged were dropped.
Exact evaluated payload duplicates and family leakage are zero.

Family splits precede transformations: calibration 1,368 / development 1,367 /
test 1,367 cases, 100 families in each. Fresh primary DeBERTa predictions were not
used for tuning. Qwen candidate test predictions had already been observed during
this engineering iteration, so the complete iteration is not a blind evaluation.
V2 outcomes were used to refine general discussion grammar and are explicitly
known regression outcomes. Mechanisms overlap between different scenarios;
the corpus is authored, synthetic and correlated, not an external population estimate.

Calibration/development were used for implementation and candidate selection.
DeBERTa production weights/revision and near-one threshold remain fixed. Model
candidate scores are categorical votes encoded as .99/.50/.01, not probabilities.
The refined candidate is measured separately and is not deployed automatically.
All classification metrics are distinct from complete OPA authorization, warning
volume and actual application utility.

## Final measurements

The unchanged v2 test has 896 cases: 584 attacks and 312 benign. Its outcomes
are known regression data. Fresh and combined measurements are reported separately.

| Detector | Previous F1 / recall / FPR | Current F1 / recall / FPR | Previous TP / FP / TN / FN | Current TP / FP / TN / FN |
|---|---|---|---|---|
| AI | .6702 / 53.60% / 11.86% | .6969 / 53.94% / 1.60% | 313 / 37 / 275 / 271 | 315 / 5 / 307 / 269 |
| Rules | .6797 / 53.77% / 8.33% | .7101 / 55.99% / 3.21% | 314 / 26 / 286 / 270 | 327 / 10 / 302 / 257 |
| Hybrid | .7882 / 71.06% / 17.31% | .8343 / 73.29% / 4.49% | 415 / 54 / 258 / 169 | 428 / 14 / 298 / 156 |

The AI gain is mainly discussion discrimination: 32 fewer false positives and two
additional true positives. There is no model retraining or threshold reduction.
Rule recall adds 13 cases through preprocessing/action evidence; hybrid finds 13
more attacks while producing 40 fewer false positives. AI-only correct discoveries
remain 101, and rule-only correct discoveries rise from 102 to 113. Improved hybrid
F1 must not be confused with sufficient recall.

Legacy 72-case test results do not regress: AI F1 .8000 / recall 66.67% / FP0;
rules and hybrid F1 1.0000 / recall 100% / FP0. All 358 Python tests, 27 Rego tests
and Ruff checks pass with zero Python failures, errors or skips. The full self-test
still exits with failure because three unchanged v2 metric gates remain unmet:

- Rules F1 .7101 is below .75.
- Rules FNR .4401 exceeds .35.
- Hybrid FNR .2671 exceeds .22.

Seven v2 gates previously failed; four now pass. No bound was changed. Model
availability, source binding, completeness, leakage and latency checks pass.

### Known regression misses and false positives

AI's five remaining false positives are four native security-discussion Base64
variants and one benign cross-field Base64 variant. Rules still block eight
security-documentation variants and two benign cross-field variants. The hybrid
union is 14. A low blocking FPR does not measure the volume of contextual WARN
findings or requests requiring operator review.

Hybrid still misses 156 attacks: 42 native override variants; twelve each for
nested injection, PII exfiltration, staged attacks, cross-tool intent, argument
manipulation, data poisoning and novel paraphrases; eleven indirect-injection and
ten policy-extraction variants; remaining fragmented, cross-argument/message,
fake-system and task-hijack cases. Hard privacy and authorization controls are
separate from these classification labels.

**All nine non-English v2 subsets still have zero blocking rule recall.** Czech,
Russian and Ukrainian remain at zero primary AI/hybrid recall on those small known
subsets. Spanish, French, Italian and Portuguese benign AI FPR falls from 87.5% to
12.5% (one of eight), but this is a correlated synthetic regression result. Native
lexicon coverage is not sufficient for those held-out paraphrases.

V2 metamorphic attack detections lost relative to detected plain variants: AI30,
rules9, hybrid19 (previous 31/10/20). Benign formatting flips are 5/2/6, so reduced
aggregate false positives do not establish formatting invariance.

### Fresh scenario test: frozen previous versus current

The fresh test has 471 cases (279 attacks, 192 benign). The previous implementation
was run from the credential-free start-of-iteration snapshot, with the same real
DeBERTa artifact and threshold. All 471 IDs and payload digests match the current
fresh test. No unavailable model results are counted as benign.

| Detector | Previous F1 / recall / FPR | Current F1 / recall / FPR | Current TP / FP / TN / FN |
|---|---|---|---|
| ai | 0.3042 / 19.35% / 11.46% | 0.3483 / 22.22% / 7.81% | 62 / 15 / 177 / 217 |
| deterministic | 0.0000 / 0.00% / 21.35% | 0.7169 / 56.27% / 1.04% | 157 / 2 / 190 / 122 |
| hybrid | 0.2784 / 19.35% / 28.65% | 0.7605 / 64.87% / 8.33% | 181 / 16 / 176 / 98 |

Fresh hybrid adds 127 correct attacks and removes 39 false positives. Rules add
157 true positives from a previous zero. AI adds eight true positives and reduces
FP from 22 to 15, but **fresh AI recall remains only 22.22%**. Fresh overlap has
24 AI-only correct detections and 119 rule-only correct detections. Greater rule
coverage can reduce the number of exclusively AI discoveries without reducing AI TP.

Fresh hybrid misses are 80 native task-override variants, 14 native protected-data
transfer variants and four reconstructed cross-field variants. Fresh FP are 14
ordinary-request variants in Spanish/Italian and two structured-code examples.
Native security discussions in this fresh test produce zero blocking FP; that
does not establish zero warning volume or zero FPR on ordinary native requests.

### Complete measured suite

The current implementation actually evaluated all 4,102 cases across all three
partitions. Test contains 1,367 cases: 863 attacks and 504 benign. The previous
combined **test** comparison below adds the two measured cohort confusion tables;
it does not claim a previous full 4,102-case run, inferred scores, ROC or latency.

| Detector | Previous combined test F1 / recall / FPR | Current F1 / recall / FPR | Current TP / FP / TN / FN |
|---|---|---|---|
| ai | 0.5694 / 42.53% / 11.71% | 0.5984 / 43.68% / 3.97% | 377 / 20 / 484 / 486 |
| deterministic | 0.5048 / 36.38% / 13.29% | 0.7123 / 56.08% / 2.38% | 484 / 12 / 492 / 379 |
| hybrid | 0.6509 / 54.35% / 21.63% | 0.8109 / 70.57% / 5.95% | 609 / 30 / 474 / 254 |

Combined hybrid gains 140 correct attack detections and removes 79 false positives
on the same test inputs. It still misses 254 attacks. Combined overlap: 125 AI-only
correct detections, 232 rule-only correct detections, 18 AI-only FP and ten rule-only
FP. These are categorical blocking results, not calibrated model probabilities.

Applying the existing robustness bounds additionally to the complete v3 suite
leaves four failures: rules F1 .7123 < .75, rules FNR .4392 > .35, hybrid F1
.8109 < .82, hybrid FNR .2943 > .22. Completeness, source/threshold integrity,
availability, FPR, AI complementarity and latency bounds pass. The three v2
self-test gate failures remain independent; neither result is relabeled a pass.

### Language visibility

| Language | Attacks / benign | AI recall / FPR | Rule recall / FPR | Hybrid recall / FPR |
|---|---:|---:|---:|---:|
| cs | 36 / 24 | 0.0% / 0.0% | 27.8% / 0.0% | 27.8% / 0.0% |
| de | 36 / 24 | 30.6% / 0.0% | 27.8% / 0.0% | 58.3% / 0.0% |
| en | 551 / 288 | 50.1% / 0.7% | 71.5% / 4.2% | 78.6% / 4.2% |
| es | 36 / 24 | 63.9% / 33.3% | 33.3% / 0.0% | 91.7% / 33.3% |
| fr | 36 / 24 | 58.3% / 4.2% | 27.8% / 0.0% | 83.3% / 4.2% |
| it | 36 / 24 | 66.7% / 33.3% | 33.3% / 0.0% | 69.4% / 33.3% |
| pl | 36 / 24 | 27.8% / 0.0% | 27.8% / 0.0% | 55.6% / 0.0% |
| pt | 36 / 24 | 33.3% / 4.2% | 33.3% / 0.0% | 63.9% / 4.2% |
| ru | 30 / 24 | 0.0% / 0.0% | 23.3% / 0.0% | 23.3% / 0.0% |
| uk | 30 / 24 | 0.0% / 0.0% | 23.3% / 0.0% | 23.3% / 0.0% |

Primary AI recall is still zero for Czech, Russian and Ukrainian across the
combined test. New rules recover some protected-data transfer cases, while native
override paraphrases remain largely undetected. Spanish and Italian combined
FPR is 33.3% despite the improved v2 discussion subset. Language coverage must
not be read as language robustness.

### Attack transformations and diagnostic evidence

| Transformation | Attack cases | AI recall | Rule recall | Hybrid recall |
|---|---:|---:|---:|---:|
| base64 | 73 | 58.9% | 50.7% | 72.6% |
| fullwidth | 73 | 45.2% | 58.9% | 74.0% |
| homoglyph | 67 | 49.3% | 59.7% | 76.1% |
| html_entities | 73 | 45.2% | 58.9% | 74.0% |
| leet | 67 | 50.7% | 52.2% | 67.2% |
| long_end | 73 | 6.8% | 54.8% | 57.5% |
| long_middle | 0 | 0.0% | 0.0% | 0.0% |
| mixed_encoding | 73 | 45.2% | 53.4% | 69.9% |
| plain | 73 | 45.2% | 58.9% | 74.0% |
| punctuation | 73 | 42.5% | 49.3% | 60.3% |
| unicode_escape | 73 | 45.2% | 58.9% | 74.0% |
| url | 0 | 0.0% | 0.0% | 0.0% |
| url_twice | 72 | 45.8% | 58.3% | 73.6% |
| whitespace | 0 | 0.0% | 0.0% | 0.0% |
| zero_width | 73 | 45.2% | 58.9% | 74.0% |

Dimensions use the explicit category/variant labels below; they are not inferred
from natural-language intent or real production traffic.

| Dimension | Cases | AI | Rules | Hybrid |
|---|---:|---:|---:|---:|
| explicit discussion/code/quoted categories (benign FPR) | 256 | 2.0% | 3.9% | 5.5% |
| quoted attack/external categories (benign FPR) | 16 | 0.0% | 0.0% | 0.0% |
| encoded variants (attack recall) | 364 | 48.1% | 56.0% | 72.8% |
| cross-field category (attack recall) | 24 | 79.2% | 83.3% | 83.3% |
| multi-turn/cross-message categories (attack recall) | 24 | 54.2% | 37.5% | 91.7% |

Combined metamorphic attack detections lost relative to detected plain variants:
AI39 / rules27 / hybrid40; benign formatting flips: 6 / 4 / 8. Failures remain
visible per family, language and transform rather than hidden by aggregate F1.

The portable [AI failure review](iteration3/false-negative-analysis.json) covers
all 1,307 primary AI misses across the three partitions and 1,568 measured windows.
Each record includes score, deployed threshold, normalized inputs, rule outcome,
language/transformation/source, missing-signal hypothesis and remediation.
Window excerpts/normalized character offsets were reconstructed offline with the
same pinned tokenizer and verified against measured view hashes, window counts
and token counts. Scores and batch latencies are actual measurements; hypotheses
are suggestions, not causal attribution. The raw benchmark's helper excerpts
are approximate; use this verified review for window-to-text association.

## Performance and validation

| Workload | AI p50 / p95 ms | Rules p50 / p95 ms |
|---|---:|---:|
| Previous v2 bulk | 136.780 / 1827.522 | 0.292 / 3.611 |
| Current v2 bulk | 174.190 / 2130.009 | 0.603 / 10.416 |
| Current full v3 bulk | 175.214 / 2051.305 | 0.580 / 10.498 |
| Alternating warm legacy, previous | 147.980 / 193.147 | 0.305 / 0.518 |
| Alternating warm legacy, current | 147.888 / 209.857 | 0.526 / 0.979 |

Warm comparisons alternate execution order on identical 72-case legacy test
inputs, two passes each, two CPU threads and trace disabled. All paired model
scores match within 1e-6. AI median is unchanged; p95 rises 8.7%, and rules add
about .22 ms median / .46 ms p95. Larger encoded/padded inputs have substantially
higher rule latency: full-suite p95 10.50 ms, below the unchanged 20 ms bound.
Sub-millisecond performance therefore applies to typical short inputs, not all
cases. These are sequential local measurements, not saturation/service throughput.

Current v2 stage p50/p95: reconstruction .021/.070 ms, preparation .667/9.458 ms,
inference 172.866/2118.913 ms. Model inference accounts for about 99.4% of summed
AI time. C++ rewriting is not justified by the measured Python preparation cost.
The Qwen candidate overlapped the first bulk run and other user services remained
running; bulk timing changes cannot be attributed solely to this implementation.
Debug tracing is opt-in; this benchmark excludes live trace/serialization and
does not separately remeasure complete normal-production gateway latency.

Current v2 DeBERTa load is 5.02 s and RSS 1198.4 MiB, versus iteration 2's
5.12 s / 1370.6 MiB. RSS is an allocator/process snapshot, not a peak memory quota.
Candidate GPU residency and CPU/client limitations are reported separately.

**Validation:** 358 Python tests, 27 Rego tests and Ruff pass. Thirty-four live
browser checks plus eight additional cohort/coverage/alert checks pass. Explicit
transport faults cover disconnect/503; real authentication, capacity, verdicts,
AI windows, OPA and alert data use the actual server. No unexpected browser
console errors or uncaught page errors. Actual TCP fragmented-secret checks
confirm AI skipping and trace withholding. Screenshots were visually reviewed.
The diagnostic p95 column describes the whole measured suite, even when a
language/cohort filter is active. Python/policy/browser passes do not override
the three failed v2 and four additional combined metric gates.

## Model study and selection

A multi-field intent experiment was rejected: on the same 203 development cases
it cut FPR to zero but recall fell to 47.2%. The model confused the input's requested
intent with its own classification task. A simpler strict label/reason schema and
clearer prompt restored development recall to 96.1%, F1 .9644 and FPR 5.3%;
calibration recall was 98.9% and FPR 3.2%. These small subsets did not predict the
larger benign-security challenge well.

The frozen refined Qwen3 4B candidate actually measured all 1,367 combined final
cases (896 known regression and 471 fresh). AI TP810 / FP75 / TN429 / FN53:
F1 .9268, recall 93.86%, FPR 14.88%. Hybrid TP831 / FP85 / TN419 / FN32:
F1 .9342, recall 96.29%, FPR 16.87%. No model failures, stable source fingerprint.
On the fresh cohort alone AI recall was 95.70% and FPR 9.38%, hybrid 96.42% and
9.90%; v2 AI FPR remained 18.27%, hybrid 21.15%. This is why the candidate was
not substituted for the production classifier despite its greater recall.

Candidate AI-only correct detections: 235 on v2 and 112 on fresh. Misses include
native overrides, fake system content, fragmented context and several extraction
or tool-intent examples. False positives cluster in regexes, incident logs,
multilingual security discussions, quoted content, scanner code and fragmented
benign explanations. Full per-language/cohort results: `candidate-final.json`.

Real candidate p50/p95: 449.73 / 684.51 ms. This uses the installed GPU-backed
Ollama service, Q4_K_M, 4,096 context; observed residency 3,178,149,969 VRAM bytes.
It is not a CPU-only result and Python client RSS excludes Ollama. The manifest
digest is recorded in the raw measured report. Its benchmark overlapped the CPU
DeBERTa run; bulk timings reflect that environment. Categorical .99/.50/.01 votes
are not calibrated probabilities. No post-test threshold adjustment, ensemble or
phrase whitelist was deployed. A pinned, bounded runtime intent provider remains
future deployment work. Candidate client construction timing is not measured
Ollama cold startup, and client RSS is not the model server's peak memory.

Iteration 2's measured Deepset, DistilBERT and Qwen 0.6B comparisons remain
historical evidence, not new runs. This iteration investigates and remeasures the
most promising installed candidate, Qwen 4B, against the fixed production DeBERTa
model. It does not claim new full-corpus measurements for every alternative.

## Guardrail boundaries and remaining deployment work

The newly fixed boundary is reconstructed privacy: individually harmless fragments
can form a credential or private value. The privacy pre-pass now withholds both
source fragments and decoded content before trace emission and AI, and the actual
pipeline enforces the denial. Joined PII is conservatively blocked; it can block
cases where an individual field could previously have been redacted. Origin-aware
redaction is a separate improvement, not a guarantee of this implementation.

OPA remains the authorization authority. The demo runs inspection and policy on
synthetic input with disabled upstream execution, so its live verdicts do not prove
the safety of real downstream tools. Buffered output inspection still cannot undo
an upstream side effect. Sensitive adapters must validate scope, resource roots,
symlinks and OS-specific device paths before execution. No new service-wide egress
or distributed admission guarantee is claimed.

Without Redis, operator inspection admission/rate limits are worker-local, as in
this demo. Existing Redis-backed inspection uses an atomic shared lease and rate
counter. Its 120-second crash-recovery lease is not a hard cluster quota through
network partitions or indefinitely hung workers; Redis tests use fakeredis rather
than a new deployment run. A logical model timeout bounds the response but cannot
physically cancel a running Torch thread. Disabled or
unavailable providers remain governed by existing failure policy; they do not
provide semantic protection. Production deployment requires the existing shared
storage, network isolation and reviewed adapter boundaries.

Docker/PostgreSQL and external MCP deployments were not rerun this iteration.
The prior real AgentDyn result of 0/5 benign tasks remains unresolved; the inert
live lab and classification improvements do not establish application utility or
production readiness. Rules still have finite language/action coverage, bounded
decoding and reconstruction, and canonical Base64 requirements. Cross-role and
unrelated fields are deliberately not joined, which leaves some staged attacks
outside reconstruction. No external paging, notification or alert acknowledgment
workflow has been implemented.

## Executed plan, unmet acceptance and next priorities

All seven implementation/measurement steps in the plan were executed. The
credential-free previous snapshot and measured baseline are retained. Bounded
preprocessing/context rules, reconstructed privacy, new family-isolated scenarios,
request alerts, guided/mobile UI, real-model/candidate measurements and browser
interaction checks are complete. Existing uncommitted work was preserved.

| Acceptance area | Outcome |
|---|---|
| Larger evaluated suite and split integrity | 4,102 cases, +52.6%; 300 authoring families; zero exact duplicates/leakage |
| Legacy regression protection | Unchanged AI .800 F1; rules/hybrid 1.000; no held-out FP |
| V2 hybrid recall/FPR improvement | 71.06% -> 73.29% recall; 17.31% -> 4.49% FPR |
| Fresh scenario improvement | 19.35% -> 64.87% hybrid recall; 28.65% -> 8.33% FPR |
| Real AI complementarity | 125 AI-only correct combined test discoveries, 24 in fresh cohort |
| Executable tests, policy, lint and browser interaction | 358 Python / 27 Rego / 42 browser checks; Ruff passes |
| Authentic live pipeline and operator visibility | Real DeBERTa/OPA, SSE windows/stages, grouped alerts, cohort/language diagnostics |
| Privacy-safe reconstructed evidence | Plain/encoded fragment denials skip AI; source/decoded values withheld |
| Performance | Warm AI median unchanged; p95 +8.7%; full-suite rule p95 10.50 ms within 20 ms bound |
| Broad detection targets | Three v2 and four additional combined gates remain failed |
| Native-language robustness | Not achieved; zero combined primary AI recall in cs/ru/uk, substantial native override misses |
| Better default model / deployment utility | Candidate FPR too high; no automatic switch; AgentDyn utility and external deployment remain unresolved |

The next development cycle should prioritize native override morphology and
task-intent coverage, ordinary Spanish/Italian benign requests, provenance-aware
reconstruction of currently missed staged context, and a pinned intent-provider
strategy validated against a new independent benign challenge before deployment.
Origin-aware joined PII redaction and persistent alert lifecycle are also useful
follow-ups. Current test outcomes are now known; future tuning needs newly isolated
families rather than treating this same final set as unseen.

## Evidence and reproduction

The measured source fingerprint is
`a98b126c2d0e5ccdf99e87a0d3c2ffa56aba2654aa9a655ac226152e592bd059`.
The complete v3 dataset SHA-256 is
`018d834e3d96fe1098a1e27324ef2ad9fd8f616d97991e4eca5197a837cef1b0`.
The previous credential-free source archive SHA-256 is
`930a4aad0df6b471c4fdfef165fdc76b5be541fb64316669cc7b96b1752d121c`.
All final primary/candidate/paired reports match the frozen source. Local private
capability credential files and signing keys are excluded from the source archive.

Portable evidence:

- [Measurement summaries and validation](iteration3/measurements.json)
- [Same-test previous/current comparison](iteration3/comparison.json)
- [Dataset quality and split separation](iteration3/dataset-quality.json)
- [Verified AI failure windows](iteration3/false-negative-analysis.json)
- [False positives](iteration3/current-v3-false-positives.json) and [disagreements](iteration3/current-v3-disagreements.json)
- [Evaluation dimensions](iteration3/dimensions.json) and [error categories](iteration3/error-summary.json)
- [Unchanged combined gates](iteration3/combined-gates.json)
- [Candidate development](iteration3/candidate-development.json) and [final candidate](iteration3/candidate-final.json)
- [Alternating warm performance](iteration3/paired-performance.json)
- [Browser checks](iteration3/browser-qa.json), [cohort/alert browser checks](iteration3/diagnostic-browser.json), [live privacy checks](iteration3/live-privacy.json)
- [Desktop lab](iteration3/lab-desktop.png), [mobile lab](iteration3/lab-mobile.png), [request alerts](iteration3/alerts-desktop.png), [diagnostics](iteration3/diagnostics-desktop.png)
- [Exact iteration changes](iteration3/change-summary.json) and [freeze conditions](iteration3/freeze.json)

Reproduce inside this repository:

```powershell
.\.venv\Scripts\python.exe scripts\self_test.py --robustness
.\.venv\Scripts\python.exe scripts\robustness_eval.py --corpus fresh-v3 --output artifacts/iteration3/current-fresh-v3.json --name iteration3-fresh-final
.\.venv\Scripts\python.exe scripts\robustness_eval.py --previous --snapshot docs/iteration3/previous-source.zip --corpus fresh-v3 --splits test --output artifacts/iteration3/previous-fresh-v3.json --name frozen-previous-fresh
.\.venv\Scripts\python.exe scripts\robustness_eval.py --candidate qwen-4b --corpus v3 --splits test --output artifacts/iteration3/qwen-4b-final-v3.json --name refined-intent-final
.\.venv\Scripts\python.exe scripts\paired_detection_performance.py
.\.venv\Scripts\python.exe scripts\iteration3_review.py
.\.venv\Scripts\python.exe scripts\live_demo.py
# In another terminal, against that owned demo:
.\.venv\Scripts\python.exe scripts\browser_qa.py --url http://127.0.0.1:8010
.\.venv\Scripts\python.exe docs\iteration3\diagnostic_browser.py
```

The self-test's metric failure exit is expected until the reported recall gates
are met. Qwen evaluation requires the existing local Ollama service/model. The
live-demo command refuses already occupied ports, including an already-running
copy of this demo. Raw complete result rows remain in `artifacts/iteration3/`;
portable summaries do not pretend to contain every per-case score. Rebuilding
the seed configuration is optional and deterministic; code/config changes mark
current-source evidence stale and require new measurement.
