FROM python:3.12-slim
WORKDIR /srv/aicl
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock && useradd --uid 10001 --create-home aicl
COPY --chown=aicl:aicl app app
COPY --chown=aicl:aicl demo demo
COPY --chown=aicl:aicl config config
COPY --chown=aicl:aicl opa opa
USER aicl
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
