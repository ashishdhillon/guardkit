FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY guardkit ./guardkit
RUN pip install --no-cache-dir ".[api]" \
 && useradd --create-home --uid 10001 app
USER app
ENV GUARDKIT_POLICY=/app/policy.yaml
COPY --chown=app examples/policy.yaml /app/policy.yaml
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/health', timeout=2)" || exit 1
CMD ["uvicorn", "guardkit.api:create_app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8080"]
