# Docker Example

Small Docker example for running `cb-events` with the included event handler example.

Builds the local package from the repository and runs: `examples/event_handling.py`

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
