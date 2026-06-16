# Devices & sessions

Every login is a separate server-side session, so you can show users where they're signed in
and let them sign out of one device or all of them.

These aren't built-in routes. crudauth exposes the session manager as `auth.sessions`
whenever a `SessionTransport` is configured (the default), and you add the endpoints your UI
needs on top of it:

```python
auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")  # SessionTransport by default
app.include_router(auth.router)
# auth.sessions.list_for_user / revoke / revoke_all are now available
```

See [Getting started](../../getting-started.md) for the base app. The examples below are
routes you add to your own `app`.

## List a user's sessions

`list_for_user` returns one entry per active session, with device info parsed from the user
agent and a flag marking the current one:

```python
@app.get("/account/sessions")
async def sessions(request: Request, user: Principal = Depends(auth.current_user())):
    current = request.cookies.get("session_id")
    return await auth.sessions.list_for_user(user.user_id, current_session_id=current)
# [{ "session_id", "device", "ip", "created_at", "last_activity", "current" }, ...]
```

## Revoke one session

`revoke` takes an owner id so a user can only revoke their own sessions:

```python
@app.post("/account/sessions/{session_id}/revoke")
async def revoke(session_id: str, user: Principal = Depends(auth.current_user())):
    ok = await auth.sessions.revoke(session_id, owner_id=user.user_id)
    return {"revoked": ok}
```

If `session_id` doesn't belong to `owner_id`, nothing is revoked and it returns `False`.

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
