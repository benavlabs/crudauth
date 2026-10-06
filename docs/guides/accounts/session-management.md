# Devices & sessions

Every login is a separate server-side session, so you can show users where they're signed in
and let them sign out of one device or all of them.

## Built-in routes (opt-in)

Pass `management_routes=True` to the `SessionTransport` and CRUDAuth mounts the device-management
routes for you:

```python
auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[SessionTransport(management_routes=True)],
)
app.include_router(auth.router)
```

| Route | What it does |
|---|---|
| `GET /sessions` | list the user's active sessions (`SessionInfo[]`; `current` flags the caller's) |
| `DELETE /sessions/{id}` | revoke one session (ownership-checked; 404 if not found or not yours) |
| `POST /logout-all` | revoke all sessions; `?keep_current=true` keeps the calling one |
| `POST /csrf/refresh` | re-mint the CSRF cookie when it's lost but the session is still valid |

All but `/csrf/refresh` run behind a session principal, so the unsafe verbs are CSRF-protected
automatically. `/csrf/refresh` is the deliberate exception: it resolves the session cookie directly
(requiring a valid CSRF header to *refresh* CSRF would defeat the recovery purpose) and self-heals,
returning the existing token unchanged when it's already valid. The routes are opt-in (`False` by
default) because adding endpoints and a device list isn't universally wanted.

## Rolling your own

If you need a different shape, CRUDAuth exposes the session manager as `auth.sessions` whenever a
`SessionTransport` is configured, and you build the endpoints your UI needs on top of it. The
examples below are routes you add to your own `app`.

## List a user's sessions

`list_for_user` returns one entry per active session, with device info parsed from the user
agent and a flag marking the current one:

```python
@app.get("/account/sessions")
async def sessions(request: Request, user: Principal = Depends(auth.current_user())):
    current = request.cookies.get("session_id")
    return await auth.sessions.list_for_user(user.user_id, current_session_id=current)
# [{ "id", "device", "ip", "created_at", "last_activity", "current" }, ...]
```

`id` is `auth.sessions.session_handle(session_id)`, the key the session is stored under (an HMAC
of the session id keyed with `SECRET_KEY`). The session id is the cookie value, so it never goes
in a response, and the handle can't be turned back into it. A handle isn't a secret: anyone who
can read the session store sees every handle, but without `SECRET_KEY` none of them becomes a
cookie, and revoking by handle is limited to the owner's own sessions.

## Revoke one session

`revoke_by_handle` takes the `id` from the list and an owner id, so a user can only revoke their
own sessions:

```python
@app.post("/account/sessions/{session}/revoke")
async def revoke(session: str, user: Principal = Depends(auth.current_user())):
    ok = await auth.sessions.revoke_by_handle(session, owner_id=user.user_id)
    return {"revoked": ok}
```

If none of the owner's sessions has that handle, nothing is revoked and it returns `False`.
`revoke(session_id, owner_id=...)` does the same with a real session id, for server-side code.

## Sign out everywhere

`revoke_all` drops every session for a user. Pass `exclude` to keep the current one, which is
the usual "sign out my other devices":

```python
@app.post("/account/sign-out-others")
async def sign_out_others(request: Request, user: Principal = Depends(auth.current_user())):
    current = request.cookies.get("session_id")
    count = await auth.sessions.revoke_all(user.user_id, exclude=current)
    return {"signed_out": count}
```

A password reset is a good place to call `revoke_all` so a compromised account can be fully
locked out.

## The session cap

`max_sessions_per_user` (default 5) bounds how many concurrent sessions a user can hold. When
a new login would exceed the cap, the oldest session is evicted automatically.

```python
SessionTransport(max_sessions_per_user=5)
```

---

[Next: Storage & lifespan →](../infra/storage.md){ .md-button .md-button--primary }
