FROM dhi.io/python:3.14-alpine3.23-dev@sha256:314cee7c7d26e381abf172a8fe75f73d88c5b67947c18f049f789d8ce1960aac AS builder

ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir uv==0.9.16

WORKDIR /tmp
COPY uv.lock pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    uv sync --frozen --no-dev --group=examples && \
    uv build && \
    /opt/venv/bin/pip install --no-cache-dir dist/*.whl

FROM dhi.io/python:3.14-alpine3.23@sha256:e5a6eb30a80566061aadb6213b45dd7b033bc59f859226f60e5e41767223387b AS runtime

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=1000:1000 examples/example.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["python", "-u", "example.py"]
