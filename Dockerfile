FROM python:3.13-slim-bookworm AS builder

WORKDIR /tmp
COPY uv.lock pyproject.toml README.md ./
COPY src/ ./src/

RUN pip --quiet --no-cache-dir install uv==0.9.2 && \
    python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv sync --frozen --no-dev && \
    uv pip install .

FROM al3xos/python-distroless:3.13-debian12

WORKDIR /app
COPY --chown=1000:1000 examples/example.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["/opt/venv/bin/python", "-u", "example.py"]
