FROM python:3.14-slim-bookworm AS builder

ENV UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /tmp
COPY uv.lock pyproject.toml README.md ./
COPY src/ ./src/

RUN pip --quiet --no-cache-dir install uv==0.9.11 && \
    python -m venv /opt/venv && \
    uv sync --frozen --no-dev --group=examples && \
    /opt/venv/bin/pip install .

FROM python:3.14-slim-bookworm AS runtime

WORKDIR /app
COPY --chown=1000:1000 examples/example.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["/opt/venv/bin/python", "-u", "example.py"]
