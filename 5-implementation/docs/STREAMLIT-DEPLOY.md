# Streamlit deployment

The dashboard runs real gateway HTTP calls and streams the actual detector stages. It never
uses canned detector decisions. Session prompts, reports and tokens are not shared by a cache.

## Local run

From `5-implementation` with Python 3.12 and the pinned model installed:

```powershell
python -m pip install -e ".[test,semantic,dashboard]"
python scripts/download_models.py --model deberta
python scripts/final_demo.py --streamlit
```

Open `http://127.0.0.1:8502`. Connect with `demo-admin-token`. The native dashboard is
`http://127.0.0.1:8012/dashboard`; both use the same gateway and scoped accounting.
All services bind loopback. Ctrl+C stops only this launcher's owned processes.

## Free Community Cloud through QQFCoding

Deploy repository **QQFCoding/Sharpe3_Goldman**, branch containing this iteration, entrypoint
**5-implementation/cloud/streamlit_app.py**, **Python 3.12**. Keep the repository private; authorize its existing
GitHub access in your own account. In Advanced settings → Secrets, set:

```toml
AICL_CLOUD_STANDALONE = "true"
```

The standalone demo starts OPA, the pinned real DeBERTa classifier, the real gateway and inert
issue-tracker/summarizer services on loopback. It downloads weights using the committed SHA256
lock. No live provider credentials are needed. Public visitors can run bounded inert inspections
and propose an issue-triage report; audit, reload and approval require the operator connection.
Budgets, issue data and audit are process memory and reset on restart. This is a demo deployment.
To enable operator features, also set `AICL_CLOUD_OPERATOR_TOKEN` to your own random value of at
least 24 characters in Cloud Secrets, and enter that value in the sidebar. Without this setting
the runtime generates an internal ephemeral token; public visitors cannot approve writes or
read other sessions' investigations. Never use a production credential as this demo token.

`5-implementation/cloud/requirements.txt` pins the frontend/model packages and uses an official CPU Torch wheel,
avoiding CUDA libraries. Community Cloud checks dependencies beside the entrypoint before the
repository root. [Dependency documentation](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies).

The model is approximately 737 MB on disk and prior local gateway RSS was approximately 1.2 GB,
before Streamlit overhead. Cold start, download connectivity and cloud memory limits can prevent
startup. The app reports unavailable startup and does not substitute a fixture classifier.
The final Windows validation does not prove the free Linux quota is sufficient.

## Existing gateway mode

For a persistent deployment use the production gateway with Redis/PostgreSQL and real identity
configuration, and deploy this frontend with:

```toml
AICL_CLOUD_STANDALONE = "false"
AICL_GATEWAY_URL = "https://gateway.example.com"
```

The configured gateway origin is server-controlled. Remote origins require HTTPS; requests do
not follow redirects or environment proxies. Operators enter their own token per session.
Never store a shared production admin token in a public app. `secrets.toml` is ignored by Git;
use the Cloud secrets interface. [Secrets documentation](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/secrets-management).

## Deployment status

The current environment exposes no usable browser session (inventory empty; in-app browser
unavailable). GitHub is connected, but Streamlit Cloud authentication/deployment is not available
through that connector. A public URL must be verified in the QQFCoding Cloud workspace before
claiming hosting is complete. [Community Cloud deployment steps](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app).
