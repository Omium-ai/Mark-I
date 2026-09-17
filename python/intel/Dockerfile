# mark1-intel — FastAPI on uv (13 §8.2). Build from the repo ROOT:
#   docker build -f python/intel/Dockerfile --build-arg REVISION=$(git rev-parse HEAD) -t omium/mark1-intel:<sha7> .
FROM python:3.12-slim-bookworm AS builder
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY proto/gen/python ./proto/gen/python
COPY python ./python
# --no-editable: workspace members land as real wheels in the venv, so nothing points back at /app/python.
RUN uv sync --frozen --no-dev --no-editable --package mark1-intel

FROM python:3.12-slim-bookworm
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/Omium-ai/Mark-I" \
      org.opencontainers.image.revision="$REVISION"
# apt upgrade: the slim tag lags stable-security by weeks; trivy blocks on fixed HIGHs (deploy/images/README.md).
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 65532 nonroot && useradd -u 65532 -g 65532 -m nonroot
WORKDIR /app
COPY --from=builder --chown=65532:65532 /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
EXPOSE 8000
USER 65532:65532
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
