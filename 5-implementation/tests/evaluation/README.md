# Evaluation contract

Normal tests check corpus splits, metric arithmetic, and finite mutations without
model weights. The original cases live in `app/evaluation/corpus.py`.

`make semantic-eval` separately evaluates real pinned local weights and calibrates
on 30 cases before reporting 30 held-out cases. `make redteam` exercises the gateway
with inert tools; `make redteam-semantic` uses the real public classifier. The runner
reports prohibited sink execution separately from malicious prompt reach, and
measures benign fixture completion. It does not measure model answer quality.

Generated full reports remain in `artifacts/`; the checked-in measurements and
limitations are in `docs/PHASE2.md` and `docs/measurements.json`.
