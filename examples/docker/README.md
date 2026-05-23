## Docker Example

Small Docker example for running `cb-events` with the event handler example.

Builds the local package from the repository and runs: `examples/event_handling.py`

# Build

Run this from the repository root:

```bash
docker build \
  -f examples/docker/Dockerfile \
  -t mountaingod2/cb-events:develop .
```

# Run

Pass the required values as environment variables:

```bash
docker run --rm \
  -e CB_EVENTS_URL="https://eventsapi.chaturbate.com/events/your_username/your_api_token/" \
  mountaingod2/cb-events:develop
```
