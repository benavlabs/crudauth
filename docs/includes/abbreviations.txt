*[Principal]: crudauth's identity object: who the request is, independent of how it authenticated (user_id, scopes, transport, the resolved user row).
*[principal]: crudauth's identity object: who the request is, independent of how it authenticated (user_id, scopes, transport, the resolved user row).
*[transport]: A way a request proves identity (cookie session, bearer token, ...). crudauth resolves any transport to one Principal.
*[transports]: Ways a request proves identity (cookie session, bearer token, ...). crudauth resolves any transport to one Principal.
*[CSRF]: Cross-Site Request Forgery: a forged cross-origin request that rides the user's cookie. crudauth blocks it with a synchronizer token.
*[JWT]: JSON Web Token: a signed, stateless token carried in the Authorization header.
*[scopes]: Capability strings carried by a credential; a route can require a subset of them.
*[sudo]: A short-lived re-authentication window required before sensitive actions.
*[lockout]: Temporary blocking of logins after repeated failures, with escalating backoff.
*[bearer token]: A stateless JWT sent in the Authorization header; good for APIs, mobile apps, and CLIs.
*[session]: A server-side record keyed by a cookie; can be revoked at any time.
*[idempotent]: An operation that has the same effect whether run once or many times.
