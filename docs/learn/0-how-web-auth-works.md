# How web authentication works

HTTP has no memory; each request arrives on its own, and the server has no idea it just handled a request from the same person a second ago. That single fact is where all of web authentication comes from - if the server forgets you between requests, then every request has to carry proof of who you are. Everything else (cookies, tokens, sessions) is a different answer to one question: how does that proof travel, and how does the server trust it?

This page is the model CRUDAuth is built on. There's almost no CRUDAuth code here yet; it's the vocabulary the rest of the documentation uses.

**Authentication** answers "who are you." **Authorization** answers "what are you allowed to do." A login proves identity, which is authentication; checking that the logged-in user is an admin before letting them delete a record is authorization. They're separate steps, and CRUDAuth does both: a transport authenticates the request, and the gates on a route authorize it. Keeping them distinct in your head makes everything after this clearer.

We'll focus on the authentication half first: how a request proves who it's from.

## Carrying identity: sessions or tokens

There are two common ways to carry proof of identity on each request, and the choice between them drives most of CRUDAuth's design.

A **session** keeps the state on the server. When you log in, the server creates a record (something like "session 9f3a is user 42, expires at noon") and hands the browser an opaque id. The browser sends that id back on every request, and the server looks it up; the server holds the truth, so it can revoke a session the instant it wants to. The cost is one lookup per request.

A **token** keeps the state in the proof itself - the most common kind is a JWT. The server signs a small blob that says "user 42, expires at noon" and gives it to the client; the client sends it back, and the server checks the signature; no lookup, no stored state. That makes tokens cheap and easy to scale, but it also means the server can't take one back before it expires: a token is trusted as long as its signature is valid. That's why token systems keep them short-lived and mint fresh ones with a separate refresh step.

Neither is better; they fit different callers. A session stores its state on the server, can be revoked the moment you want, costs a lookup on every request, and fits browsers. A token carries its state with it, can't be pulled back before it expires, costs only a signature check, and fits APIs, mobile apps, and command-line tools.

<p align="center">
  <img src="../assets/diagrams/session-vs-token-light.png#only-light" alt="A session sends a cookie id the server looks up in a session store, so it is revocable and costs one lookup per request and fits browsers; a token sends a signed blob the server verifies with no lookup, so it cannot be revoked early but is cheap and fits APIs, mobile apps, and CLIs" width="100%">
  <img src="../assets/diagrams/session-vs-token-dark.png#only-dark" alt="A session sends a cookie id the server looks up in a session store, so it is revocable and costs one lookup per request and fits browsers; a token sends a signed blob the server verifies with no lookup, so it cannot be revoked early but is cheap and fits APIs, mobile apps, and CLIs" width="100%">
</p>

CRUDAuth doesn't make you choose globally. It supports both as transports, and a route never has to know which one a given request used. We'll come back to why this is relevant at the end.

But choosing a transport isn't free; each one brings its own failure mode, and the session's starts with the very thing that makes it convenient: the cookie.

## Why cookies drag in CSRF

Sessions ride in a **cookie**, because cookies have a property nothing else does: the browser attaches them to every request to that site, automatically. You don't write any code to send the session cookie; it just goes.

That convenience is also the catch: if a malicious page makes your browser fire a request at your bank, the browser cheerfully attaches your bank cookie too; the server sees a valid session and acts on it. That's **CSRF**, cross-site request forgery: the attacker never sees your cookie, they only trigger a request that carries it.

The fix is to require something on each state-changing request that the attacker can't supply: a secret token your own frontend reads and echoes back in a header. A forged cross-site request can't read that token, so the server rejects it. CRUDAuth's session transport does this with a synchronizer token, and you'll see the mechanics in chapter 4.

<p align="center">
  <img src="../assets/diagrams/csrf-light.png#only-light" alt="A same-origin request from your frontend sends the session cookie plus the X-CSRF-Token header and gets 200; a forged cross-origin request sends the cookie but cannot supply the token and gets 403" width="100%">
  <img src="../assets/diagrams/csrf-dark.png#only-dark" alt="A same-origin request from your frontend sends the session cookie plus the X-CSRF-Token header and gets 200; a forged cross-origin request sends the cookie but cannot supply the token and gets 403" width="100%">
</p>

Tokens sidestep CSRF because they're sent explicitly in an `Authorization` header rather than automatically. But they raise a different question: where does a browser keep one? Store it somewhere JavaScript can read, and any cross-site-scripting bug can steal it; store it in an httpOnly cookie, and it's safe from scripts but back to riding along automatically, which is the CSRF problem again. There's no free lunch here, only trade-offs, which is why tokens are mostly the right tool for non-browser clients.

All of this assumes the login already happened: that the server confirmed who you are before it issued any session or token. That confirmation rests on one more rule.

## Passwords are never stored

The server never keeps your password; it keeps a one-way **hash** of it, computed with a slow, salted algorithm like bcrypt. "One-way" means you can't recover the password from the hash; "slow" means an attacker who steals the database can't test billions of guesses cheaply. "Salted" means two users with the same password get different hashes. On login, the server hashes what you typed and compares it to the stored hash. CRUDAuth handles this for you, and chapter 1 covers the ways even this step gets botched.

<p align="center">
  <img src="../assets/diagrams/password-hash-light.png#only-light" alt="A typed password is run through bcrypt (slow and salted) into a hash, which is compared against the stored hash; the password itself is never stored and cannot be recovered" width="100%">
  <img src="../assets/diagrams/password-hash-dark.png#only-dark" alt="A typed password is run through bcrypt (slow and salted) into a hash, which is compared against the stored hash; the password itself is never stored and cannot be recovered" width="100%">
</p>

## One identity, however it arrived

Step back and notice what every approach here has in common: a cookie session, a bearer token, something you write yourself - each is one way to answer a single question. Who is this request, and what may they do? Your application logic shouldn't care which mechanism delivered the answer.

> Every transport answers the same question: who is this request, and what may they do? Your routes gate on the answer, never on how it arrived.

That's the idea CRUDAuth is built around: whatever transport authenticates a request resolves to a single **Principal** - the user's id, their scopes, whether they're a superuser, and the loaded user row. Your routes gate on the Principal, never on the transport.

<p align="center">
  <img src="../assets/diagrams/identity-light.png#only-light" alt="A browser session cookie and an API bearer token both funnel through CRUDAuth into one Principal carrying user_id, scopes, is_superuser, and the user row, which the route gates on regardless of transport" width="100%">
  <img src="../assets/diagrams/identity-dark.png#only-dark" alt="A browser session cookie and an API bearer token both funnel through CRUDAuth into one Principal carrying user_id, scopes, is_superuser, and the user row, which the route gates on regardless of transport" width="100%">
</p>

Hold onto that picture, it's the reason adding a transport later doesn't ripple through your authorization code, and it's the spine of everything in the chapters ahead.

Before we build on this model, we need to see the specific failures it has to defend against.

---

[Next: How auth goes wrong →](1-how-auth-goes-wrong.md){ .md-button .md-button--primary }
