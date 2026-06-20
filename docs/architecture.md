# Architecture

CRUDAuth is ports-and-adapters with feature slices and a single composition root. This page
is the map: where things live, which way imports are allowed to point, and how to add a
transport, OAuth provider, or backend without a cross-cutting edit.

<p align="center">
  <img src="assets/diagrams/architecture-light.png#only-light" alt="Four layers left to right: composition root (crud_auth), features (register, email, oauth), subsystems (transports, storage), and cross-cutting leaves (constants, utils); each layer imports only inward and inner layers never import outer ones" width="100%">
  <img src="assets/diagrams/architecture-dark.png#only-dark" alt="Four layers left to right: composition root (crud_auth), features (register, email, oauth), subsystems (transports, storage), and cross-cutting leaves (constants, utils); each layer imports only inward and inner layers never import outer ones" width="100%">
</p>

## The one rule

**Imports point inward.** Outer layers may import inner ones; inner layers never import outer
ones. If a leaf imports a feature, or two features import each other, something is in the
wrong layer.

## The layers

**Framework spine** is the set of ports plus the composition root: `crud_auth.py`
(`CRUDAuth`, the one object you configure and mount), `core.py` (the `Transport` port and the
shared runtime types), `principal.py`, `repository.py`, `identity.py` (the account-shape
contract), and `hooks.py`. `CRUDAuth` is the only module allowed to import from every layer.

**Cross-cutting leaves** depend on nothing internal: `constants.py`, `exceptions.py`,
`utils.py`. The registration gating contract (`REGISTRATION_ALLOWED_FIELDS`) lives in
`constants.py` because the spine consumes it.

**Features** are vertical slices, each owning its router, service, schemas, and constants:
`register/`, `email/`, `oauth/`. A feature may import the spine, the leaves, and the
subsystems, but never another feature.

**Pluggable subsystems** are a `base.py` port over a `backends/` adapter set, so you swap the
backend without touching callers: `transports/` (session, bearer), `ratelimit/`, and
`storage/`.

## The identity contract

<p align="center">
  <img src="assets/diagrams/identity-contract-light.png#only-light" alt="Two inputs, your model (make_auth_identity, whose columns are the shape) and IdentityConfig (the intent: login and recovery), are validated against each other at startup and fail closed; the same machinery yields an email-plus-username account with email recovery, a username-login account with phone recovery, or a username-only account with no recovery" width="100%">
  <img src="assets/diagrams/identity-contract-dark.png#only-dark" alt="Two inputs, your model (make_auth_identity, whose columns are the shape) and IdentityConfig (the intent: login and recovery), are validated against each other at startup and fail closed; the same machinery yields an email-plus-username account with email recovery, a username-login account with phone recovery, or a username-only account with no recovery" width="100%">
</p>

An account's *shape* is read from the model, never configured in two places. The user columns
come from `models/` (the `make_auth_identity` factory, with `AuthUserMixin` its default), and the
`repository.py` logical-field contract reads them back, so nothing else touches the model
directly. `IdentityConfig` (`identity.py`) carries only the intent a schema can't express: the
login resolution order and the recovery factor. At construction `CRUDAuth` validates that config
against the model's actual columns and fails closed, which keeps the model the single source of
truth and stops the config from drifting from it.

The recovery factor is what makes verification and reset factor-agnostic. "Verified" means the
recovery factor is proven controlled (email is the special case, a phone the general one), and
recovery tokens are handed to `DeliveryChannel` adapters, so an account recovers over email, SMS,
or any channel you implement. The `verify` and `reset` request endpoints are shaped to the factor,
so a phone-recovery app drives them with a phone number.

## A request's path

<p align="center">
  <img src="assets/diagrams/request-flow-light.png#only-light" alt="A request arrives with a cookie or token; the transport loop validates the credential, enforces CSRF, and resolves the user into one Principal cached on request.state; the gates (superuser, scopes, check) then authorize it" width="100%">
  <img src="assets/diagrams/request-flow-dark.png#only-dark" alt="A request arrives with a cookie or token; the transport loop validates the credential, enforces CSRF, and resolves the user into one Principal cached on request.state; the gates (superuser, scopes, check) then authorize it" width="100%">
</p>

When a route depends on `current_user()`, CRUDAuth runs the transport loop once and caches the
result on `request.state`, so combining gates (and a `KeyBy.USER` rate limit that resolves the
user internally) does one authentication, not several:

1. Each selected transport is tried in order. A transport returns `None` when its credential
   is **absent** (move on) but raises for one that's **present but invalid** (a tampered
   credential is an attack signal, not "anonymous").
2. The winning transport validates its credential, enforces CSRF on unsafe methods where it
   applies, resolves your user row, and returns a `Principal`.
3. The gates you asked for (`superuser`, `verified`, `scopes`, `check`) run on that shared
   `Principal`, per call.

## Adding things

<p align="center">
  <img src="assets/diagrams/ports-light.png#only-light" alt="Callers depend on a port (base.py); memory, redis, and your own backend each implement it, so a backend can be added without touching callers" width="100%">
  <img src="assets/diagrams/ports-dark.png#only-dark" alt="Callers depend on a port (base.py); memory, redis, and your own backend each implement it, so a backend can be added without touching callers" width="100%">
</p>

- **An OAuth provider:** add `oauth/providers/<name>.py` implementing the `provider.py` port,
  and register it in `factory.py`.
- **A rate-limit or storage backend:** add `backends/<name>.py` implementing the subsystem's
  `base.py`. Callers reach it through the port.
- **A transport:** add a package under `transports/` whose class implements the `Transport`
  port from `core.py`, and pass an instance in `transports=[...]`.
- **A delivery channel:** implement the `DeliveryChannel` port (`email/channel.py`) and pass an
  instance in `channels=[...]`, so recovery tokens route over SMS, push, or your own transport. It
  is a port owned by a feature rather than a top-level subsystem.
- **An account shape:** build the model with `make_auth_identity(identifiers=, recovery=, oauth=)`
  and a matching `IdentityConfig`; the runtime reads the shape, so username-only, phone-recovery,
  and email accounts are configuration, not forks.
- **A feature:** add a package with its own `router.py` (plus `service.py` / `schemas.py` /
  `constants.py`) and mount it from `crud_auth.py`, without importing sibling features.

## One caveat: route modules and deferred annotations

Modules that declare FastAPI routes deliberately **omit** `from __future__ import annotations`,
because FastAPI must see real types (not deferred strings) to resolve `Depends(...)` and
request-body models. This applies to `crud_auth.py`, `register/route.py`, the transports, and
the OAuth and email routers. Everywhere else, keep the `from __future__` import.
