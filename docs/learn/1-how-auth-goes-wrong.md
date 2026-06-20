# How auth goes wrong

This chapter walks the handful of failures that turn a working login into an incident; CRUDAuth handles each of them for you, but it's worth knowing what's being defended, because the same mistakes are easy to reintroduce in the code you build around it.

None of these are exotic attacks. They're the default ways auth goes wrong when you wire it by hand.

## It tells attackers which accounts exist

Send two failed logins: one for a username that doesn't exist, one for a real username with the wrong password. If the replies differ ("no such user" versus "incorrect password"), or if one comes back noticeably faster (the unknown-user path skips the expensive password check, so it returns sooner), an attacker can tell the two apart. Do that across a list of guesses and you've mapped out which accounts are real, the first step of credential stuffing, phishing, and password spraying.

<p align="center">
  <img src="../assets/diagrams/enumeration-light.png#only-light" alt="A naive login returns 'no such user' for an unknown account and 'wrong password' for a real one, with different timing, leaking which accounts exist; CRUDAuth returns the same 'Incorrect username or password' with the same timing for both" width="100%">
  <img src="../assets/diagrams/enumeration-dark.png#only-dark" alt="A naive login returns 'no such user' for an unknown account and 'wrong password' for a real one, with different timing, leaking which accounts exist; CRUDAuth returns the same 'Incorrect username or password' with the same timing for both" width="100%">
</p>

CRUDAuth returns one uniform "Incorrect username or password" for every failure, and runs a throwaway password check on the missing-user path so it takes the same time as a real one. A disabled account gets the same answer too. (One residual stays by design: someone who already knows a correct password can still tell a disabled account from a wrong password. That distinction can't be hidden without refusing the correct password.)

## It lets them guess forever

Online guessing is only slow if something slows it down. Point an attacker at a single account with no limit in place and they just keep trying; a weak password falls in minutes. The defense is a lockout that makes each round of failures cost more than the last.

<p align="center">
  <img src="../assets/diagrams/lockout-light.png#only-light" alt="After five failed attempts the first lockout is 60 seconds, then 120, then 240, doubling each round up to a maximum, and a successful login clears the counters" width="100%">
  <img src="../assets/diagrams/lockout-dark.png#only-dark" alt="After five failed attempts the first lockout is 60 seconds, then 120, then 240, doubling each round up to a maximum, and a successful login clears the counters" width="100%">
</p>

CRUDAuth counts failures per IP and per username and escalates the lockout each round, up to a cap, so a slow, paced attack keeps climbing instead of resetting. It also fails closed: if the counter backend is unreachable, logins are refused rather than waved through, so an attacker can't switch the lockout off by knocking the backend over.

## It stores passwords it shouldn't

Everyone knows not to store plaintext, the subtler mistake is storing a *fast* hash. Running MD5 or SHA-256 over a raw password is one-way, so it looks safe, but those functions are built for speed, and a stolen table of fast hashes is cracked at billions of guesses per second on a GPU. Password storage wants the opposite: a deliberately slow, salted algorithm like bcrypt, but bcrypt has its own sharp edge too. It silently ignores input past 72 bytes, so a naive setup can make two long passwords with the same first 72 bytes interchangeable.

CRUDAuth hashes with bcrypt and a per-password salt, and pre-hashes the input so the 72-byte limit never bites (the password diagram in [chapter 0](0-how-web-auth-works.md) shows the shape). You never touch any of this; you just don't get to make the choices that look fine and aren't.

## It can't take a token back

A stateless token is trusted until it expires, which is fine until you need to revoke one. A token that leaks keeps working; a user who resets their password after a compromise still has old tokens in circulation that keep working too. Long-lived tokens make the blast radius bigger.

CRUDAuth keeps access tokens short-lived and mints them from a separate refresh token, so a leaked access token expires fast. For the "cut everything off now" case, it stamps every token with a version that a password reset bumps, which invalidates every token issued before the reset in a single move.

## It lets the signup form set anything

A registration handler that copies the request body straight onto your model is a privilege-escalation bug waiting to happen:

```python
# the request body is {"email": "...", "username": "...", "is_superuser": true}
user = User(**body)   # the attacker just made themselves an admin
```

The fix is an allowlist: decide which fields a signup is allowed to set, and drop everything else. CRUDAuth's `/register` persists only `email` and `username` unless you opt a column in explicitly, and it refuses privileged fields like `is_superuser` and `email_verified` outright. Adding a column to your model never quietly becomes settable at signup.

## It trusts redirects and OAuth state

Two related mistakes show up once OAuth is involved - the first is an open redirect: a "send me back where I was" parameter that isn't validated lets an attacker craft a link on *your* domain that bounces the user to *theirs*, which is exactly what makes phishing convincing. The second is an OAuth `state` that isn't tied to the browser that started the flow, which lets an attacker complete a sign-in as themselves inside the victim's browser.

CRUDAuth checks the post-login redirect against an allowlist, and binds the OAuth `state` to a cookie set when the flow begins, so a forged or replayed callback can't go through.

## None of this is clever

That's the real lesson. Secure auth isn't about doing something brilliant; it's about not doing the small set of things that quietly go wrong. CRUDAuth's job is to make the safe behavior the default, so the only way to end up with the broken version is to go out of your way for it. Everything in the rest of this track is built on that floor.

With the model and the threats in hand, we start writing code.

---

[Next: Your first protected route →](2-your-first-protected-route.md){ .md-button .md-button--primary }
