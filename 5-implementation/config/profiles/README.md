# Configuration profiles

These full policy files are operating examples, not newly calibrated model operating points. All three remain in `mode: enforce`. Authentication, tenant boundaries, secret blocking, PII protection, model/tool allowlists, network restrictions, approvals for mutation, information flow and manifest pins remain enabled. The name *permissive* means more resource allowance and fewer semantic reviews; it does not allow arbitrary tools, private-address fetches or secret disclosure.

| Setting | Strict | Balanced | Permissive |
|---|---:|---:|---:|
| PII input/output action | BLOCK | REDACT | REDACT |
| DeBERTa review threshold | 0.15 | 0.30 | 0.60 |
| DeBERTa block threshold | 0.98 | 0.9999991655349731 | 0.9999995 |
| Semantic always-scan | yes | no | no |
| Workflow steps | 8 | 25 | 50 |
| LLM/tool calls each | 6 | 20 | 40 |
| Workflow token allowance | 12,000 | 100,000 | 200,000 |
| Workflow credit allowance | 12 | 100 | 200 |

Credits use configured accounting rates, not live provider prices. A final decision combines all controls: a configured PII `REDACT` action can still produce `REQUIRE_APPROVAL` or `BLOCK` because of independent semantic or authorization findings. Scores are risk signals, not calibrated probabilities or adherence percentages.

Install a profile by copying its contents to the gateway's configured policy path, then call authenticated `POST /admin/policy/reload` or `POST /admin/governance/reload` with `{"kind":"policy"}`. Every material edit needs a new `metadata.revision`. Changing contents without changing the active revision is rejected. Atomic validation preserves the previous policy on an invalid reload. Policy revisions also invalidate pending approvals. The threat feed path is relative to the policy file, so keep `threat-feed.yaml` alongside it.

The isolated `python scripts/judge_demo.py` copies profiles into a temporary `.tools` configuration directory and proves their effects without changing the main `config/policy.yaml`. Do not copy these policy files over a production configuration without reviewing the allowed resources and budgets for that application.

Policy actions, thresholds, allowed resources, budgets and threat-feed rules reload live. Environment settings such as semantic provider, model paths, stores, upstream URLs and authentication mode require a restart. New detector implementations or tool schemas require code changes and tests.
