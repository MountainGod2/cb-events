# syntax=docker/dockerfile:1@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
FROM ghcr.io/astral-sh/uv:alpine3.23-dhi@sha256:e8d4c10bdf24ddc76ac69467b90cd5751107fb64dca6a5d533b7c35e2e33dff4 AS uv
FROM dhi.io/python:3-alpine3.23-dev@sha256:52ea9e4208617baf9800049bc25da9b822f96458be036c45ea728b32828e9502 AS builder

ENV PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_CACHE=1 \
    UV_COMPILE_BYTECODE=1 \
    VIRTUAL_ENV=/opt/venv

COPY --from=uv /usr/local/bin/uv /usr/local/bin/uv

WORKDIR /app

COPY examples/event_handling.py examples/event_handling.py.lock ./

RUN uv venv "$VIRTUAL_ENV" && \
    uv sync --script event_handling.py --active --frozen

FROM dhi.io/python:3-alpine3.23@sha256:b9fc36b7bf632b15932f7ed298cafa2f39ef5c8318a104717bf14c87ed46ab34 AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

WORKDIR /app

COPY --chown=1000:1000 examples/event_handling.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["python"]
CMD ["event_handling.py"]
