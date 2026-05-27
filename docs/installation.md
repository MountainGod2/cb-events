# Installation

## Requirements

Python >= 3.10

## Install

```bash
pip install cb-events
```

Or with uv:

```bash
uv add cb-events
```

## Development

```bash
git clone https://github.com/MountainGod2/cb-events.git
cd cb-events
make setup
```

Useful local commands:

```bash
make help
make ci
make test
```

Optional advanced commands:

```bash
make security-full
make check-all
```

## API Token

Create a token at https://chaturbate.com/statsapi/authtoken/ with **Events API** scope.

Authorization notes:

- Events API access is token-based.
- You can create multiple tokens and delete any token to revoke its access.
- Revocation may take up to one minute after deletion.

```bash
export CB_EVENTS_URL="https://eventsapi.chaturbate.com/events/your_username/your_api_token/"
```
