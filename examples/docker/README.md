# Docker Example

Small Docker example for running `cb-events` with the included event handler example.
The image builds the package from the current repository source and runs: `examples/event_handling.py`
Runtime dependencies are exported from [uv.lock](/config/cb-events/uv.lock) during the build for reproducibility.

## Build

Run this from the repository root:

```bash
docker build \
  -f examples/docker/Dockerfile \
  -t cb-events-example .
```

## Run

Pass the required values as environment variables:

```bash
docker run --rm \
  -e CB_EVENTS_URL="https://eventsapi.chaturbate.com/events/your_username/your_api_token/" \
  cb-events-example
```

<sub>This image is intended as a usage example. For normal Python projects, install `cb-events` directly from PyPI.</sub>
