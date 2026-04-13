FROM dhi.io/python:3.14-alpine3.23-dev@sha256:ce27f69c9d49f99fa0906d4180606162cc16c2c1c6dea8700169164b1a641a5c AS builder

ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# renovate: datasource=pypi depName=uv
RUN pip install --no-cache-dir uv==0.11.2

WORKDIR /tmp
COPY uv.lock pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    uv sync --frozen --group=examples && \
    uv build && \
    /opt/venv/bin/pip install --no-cache-dir dist/*.whl

FROM dhi.io/python:3.14-alpine3.23@sha256:85af4b4082125ed0c965c55338e0b8dd85921e86fb0d1163d868808f85d6cfee AS runtime

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=1000:1000 examples/event_handling.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["python", "-u", "event_handling.py"]
