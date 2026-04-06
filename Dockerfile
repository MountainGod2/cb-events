FROM dhi.io/python:3.14-alpine3.23-dev@sha256:c07730faf95dc5189a5357a083403e64124ba1f90acfeef4b05385261b4ac7a0 AS builder

ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir uv==0.9.16

WORKDIR /tmp
COPY uv.lock pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    uv sync --frozen --group=examples && \
    uv build && \
    /opt/venv/bin/pip install --no-cache-dir dist/*.whl

FROM dhi.io/python:3.14-alpine3.23@sha256:e6aa0c22d51269a8cdefe8077a96e7f3b9eb7cbf49112557f493389de6a43bed AS runtime

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=1000:1000 examples/event_handling.py /app/
COPY --chown=1000:1000 --from=builder /opt/venv /opt/venv

USER 1000:1000

ENTRYPOINT ["python", "-u", "event_handling.py"]
