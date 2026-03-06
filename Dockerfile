FROM dhi.io/python:3.14-alpine3.23-dev@sha256:4718517ca151ef9cc2b69acd948a30889bc842e13ae94793b78486ffa56b9126 AS builder

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

FROM dhi.io/python:3.14-alpine3.23@sha256:400a115ed742d57ba86a98153440f85f24733038286a9ce43092484e8a6c0f3e AS runtime

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=1000:1000 examples/example.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["python", "-u", "example.py"]
