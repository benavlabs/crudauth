# Transports

A transport authenticates a request and returns a [Principal](principal.md). Configure them
via `transports=[...]`; the first credential present wins.

## Transport (port)

::: crudauth.Transport

## SessionTransport

::: crudauth.SessionTransport

## BearerTransport

::: crudauth.BearerTransport

## SessionManager

Server-side sessions, CSRF, device management, and login lockout. Reachable as
`auth.sessions` when a `SessionTransport` is configured.

::: crudauth.transports.session.manager.SessionManager
