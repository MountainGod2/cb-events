# syntax=docker/dockerfile:1@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
FROM dhi.io/python:3-alpine3.23-dev@sha256:52ea9e4208617baf9800049bc25da9b822f96458be036c45ea728b32828e9502 AS builder

ENV LANG=C.UTF-8
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV UV_NO_CACHE=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY --from=ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a /uv /usr/local/bin/uv

WORKDIR /app

COPY uv.lock pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    uv sync --frozen --group=examples && \
    uv build && \
    /opt/venv/bin/pip install --no-cache-dir dist/*.whl

FROM dhi.io/python:3-alpine3.23@sha256:b9fc36b7bf632b15932f7ed298cafa2f39ef5c8318a104717bf14c87ed46ab34 AS runtime

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=1000:1000 examples/event_handling.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["python", "-u", "event_handling.py"]
