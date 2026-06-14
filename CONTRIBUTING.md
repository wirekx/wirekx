# Contributing

Thanks for considering a contribution to wirekx.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

## Tests

```bash
.venv/bin/python -m pytest
```

## Security scope

wirekx v1 anonymous mode is experimental and opportunistic. It does not
authenticate peers and is not production-ready. Please do not submit changes
that describe v1 anonymous mode as a replacement for TLS, mTLS, service mesh
security, or audited production cryptography.

Security improvements are welcome, especially authenticated modes, replay
protection, and well-tested payload encryption APIs.
