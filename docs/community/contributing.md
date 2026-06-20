# Contributing

Thanks for helping improve crudauth. This page covers getting set up, the checks your change
needs to pass, the conventions the codebase follows, and how a release ships.

## Set up

CRUDAuth uses [uv](https://docs.astral.sh/uv/). Fork and clone the repo, then:

```bash
uv sync --all-extras --dev
```

That installs the package, the optional extras, and the dev tools (pytest, ruff, mypy,
fakeredis).

## The checks

A change has to pass the same three gates CI runs. Run them locally before opening a PR:

```bash
uv run ruff check crudauth tests
uv run mypy crudauth tests --config-file pyproject.toml
uv run pytest -q -p no:warnings
```

## Conventions

These keep the codebase consistent. A reviewer will ask for them, so save the round trip:

- **Imports go at the top of the file**, never inside functions.
- **Rationale goes in docstrings (a Google-style `Note:`), not inline comments.** Code should
  read like the code around it.
- **Route-defining modules omit `from __future__ import annotations`** so FastAPI can resolve
  `Depends(...)` and request-body models from real types. Everywhere else, keep it. See
  [Architecture](../architecture.md).
- **Imports point inward** (the one architectural rule): inner layers never import outer ones.
- **Tests are typed** so mypy checks them; don't bypass with config.
- **Constants live in `constants.py`** (per-module, or the top-level one), not as bare
  literals inside expressions.
- Ruff line length is 100; target Python is 3.10.

## Tests

The suite mirrors the source layout under `tests/` (`unit/`, `transports/`, `oauth/`,
`ratelimit/`, `storage/`, `core/`, ...). Put a new test next to its peers, type the test
functions, and use the shared fixtures in `tests/conftest.py` (`get_session`, `UserModel`,
`sessionmaker`).

## Pull requests

Branch off `main`, keep each change focused, and fill in the PR template (it has the checklist
above). Reference any related issue. Smaller PRs land faster.

## Releasing

Maintainers cut releases: bump `version` in `pyproject.toml` (the runtime `__version__` reads
it from package metadata, so there's nothing else to change), tag `vX.Y.Z`, publish a GitHub
release, and `uv build && uv publish`.
