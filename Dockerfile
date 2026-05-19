# syntax=docker/dockerfile:1@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
FROM ghcr.io/astral-sh/uv:alpine3.23-dhi@sha256:e8d4c10bdf24ddc76ac69467b90cd5751107fb64dca6a5d533b7c35e2e33dff4 AS uv

FROM dhi.io/python:3-alpine3.23-dev@sha256:99298a132edef75ffbac3943eabea7419a0d576bb70981f83e274a2374aad461 AS builder

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_FROZEN=1 \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON=python3 \
    VIRTUAL_ENV=/opt/venv

COPY --from=uv /usr/local/bin/uv /usr/local/bin/uv

WORKDIR /app

COPY uv.lock pyproject.toml README.md ./
COPY src/ ./src/

RUN uv venv && \
    uv sync --group=examples && \
    uv build && \
    uv pip install dist/*.whl

FROM dhi.io/python:3-alpine3.23@sha256:263eff340d66dc716725091a68c2b0c42dece20202444b46db12bc30ba6e4a70 AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --chown=1000:1000 examples/event_handling.py /app/
COPY --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["python"]
CMD ["event_handling.py"]
