# Detection iteration 3: plan and acceptance

Starting point: `DETECTION-ITERATION2.md`, not the historical 72-case result.
Current v2 test: AI F1 .6702 / recall .5360 / FPR .1186; rules .6797 /
.5377 / .0833; hybrid .7882 / .7106 / .1731. Seven broad gates fail.

1. Preserve a credential-free current source snapshot and measured baseline.
2. Improve bounded preprocessing: directive-bearing JSON keys and explicitly
   encoded short fragments; retain role/provenance boundaries and resource limits.
3. Improve instruction/data-flow/tool intent and multilingual discussion context.
   Develop on calibration/development only. Keep deployed model weights and
   threshold fixed unless a measured candidate justifies replacement.
4. Add fresh multilingual, discussion, reconstruction and action-intent scenario
   families with family isolation before transformations. Treat v2 test as a known
   regression set; fresh test outcomes are opened after implementation freeze.
5. Build request-level alert triage with severity, disposition, detector agreement,
   evidence and remediation. Keep raw findings accessible, avoid duplicate alerts.
6. Make the live lab usable on narrow screens; add a guided mixed-traffic demo,
   stage progress, expected-vs-observed results, admission visibility and clear
   refusal/error states. Every result comes from the real inert pipeline.
7. Run Python/Rego/lint, regression and fresh-corpus evaluations, a development
   model comparison, and real headless browser QA. Record latency, missed cases,
   false positives and unmet gates without weakening acceptance thresholds.

Acceptance: no legacy detection regression; measured hybrid recall/FPR improvement
on v2 regression; fresh family leakage/duplicates zero; genuine AI-only discoveries;
all executable tests pass; authenticated privacy-safe request alerts; working live
demo and mobile layout with no console errors. Broader metric gates remain fixed.
More datapoints may justify modest performance cost; report actual p50/p95 and
dataset composition. Synthetic correlations and deployment boundaries remain explicit.

Execution completed. Source/baseline are preserved; bounded preprocessing,
action/context rules, fresh families, request alerts, guided/mobile UI, real-model
measurements and browser checks are implemented and verified. Corpus grows 52.6%
to 4,102 evaluated synthetic cases with zero exact duplicates/family leakage.
Legacy metrics do not regress. V2 hybrid F1 improves .7882 -> .8343, recall
71.06% -> 73.29%, FPR 17.31% -> 4.49%. Fresh hybrid recall improves
19.35% -> 64.87% against the frozen previous implementation.

All 358 Python, 27 Rego and 42 browser checks pass; Ruff passes. Three unchanged
v2 metric gates and four additionally applied combined-v3 metric gates remain
unmet. Broad native-language robustness is not achieved. Qwen is measured but
not deployed because combined AI FPR exceeds the fixed bound. Warm AI median
is unchanged and p95 increases 8.7%; rules add under .5 ms p95 on short inputs,
with 10.50 ms p95 across the larger suite. Details, methodology and remaining
work are in [the final report](DETECTION-ITERATION3.md).
