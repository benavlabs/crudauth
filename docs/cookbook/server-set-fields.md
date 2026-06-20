# Server-set fields at signup

Most apps have columns the user shouldn't choose but every account needs: a plan or tier, an org
id, a derived display name, a `NOT NULL` column with no database default. The question for each one
is who provides the value, the client or the server, and that answer picks the knob. This recipe
wires all three, and more importantly draws the trust boundary between them.

It builds on the [email and password](email-password.md) base.

## The three knobs

| The value comes from | Use | Settable by the client? |
|---|---|---|
| the client, at signup | `register_extra_fields` | yes (you allowlist it) |
| the server, a constant | `new_user_defaults` | no |
| the server, derived | `new_user_fields` | no |

## A client-supplied field

If the user types the value at signup (a display name, say), add it to your `register_schema` and
opt the column into the write allowlist:

```python
from pydantic import BaseModel, Field

class Register(BaseModel):
    email: str
    username: str
    password: str = Field(min_length=8)
    display_name: str

auth = CRUDAuth(
    ..., register_schema=Register, register_extra_fields={"display_name"},
)
```

Without `register_extra_fields`, a `display_name` in the request body is silently dropped. The
allowlist is the only route by which a request gets to write a column.

## Server-set values: a constant and a derived one

For values the server owns, use `new_user_defaults` for constants and `new_user_fields` for anything
computed. Both run wherever CRUDAuth creates a user, password signup and OAuth alike, so you state
the rule once:

```python
def new_user_fields(ctx):
    # ctx is the server-built context: email, username, source ("register"/"oauth"),
    # the live db, the validated register_data, and the oauth profile.
    return {"name": ctx.suggested_name}

auth = CRUDAuth(
    ...,
    new_user_defaults={"tier_id": FREE_TIER_ID},   # constant
    new_user_fields=new_user_fields,               # derived (may be async, may read ctx.db)
)
```

`new_user_defaults` merges first, then `new_user_fields`, so a derived value can override a constant.
`ctx.suggested_name` is the OAuth display name, falling back to the email local-part, so the same
callback does the right thing on both signup paths.

## See it in action

Register a user, and slip a `tier_id` into the body that the client should not get to choose:

```bash
curl -X POST http://localhost:8000/register -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","username":"alice","password":"a-strong-one",
       "display_name":"Alice","tier_id":"enterprise"}'
```

The persisted row ends up with `display_name="Alice"` (you allowlisted it), `tier_id=FREE_TIER_ID`
(your default, the client's `"enterprise"` was dropped because `tier_id` isn't in
`register_extra_fields`), and `name` filled in by your callback. The client got to choose the one
field you allowed, and nothing else.

## The trust boundary is the whole point

These two groups look similar but sit on opposite sides of a line, and that line is why this is safe.
`register_extra_fields` is fed the *request body*: it's how you let a client set a column, so it's an
explicit allowlist, one column at a time. `new_user_defaults` and `new_user_fields` are fed a
*server-built context*, never the request, so a client can't influence them at all.

And underneath, both are gated the same way: a CRUDAuth-owned field (`is_superuser`,
`email_verified`, the password hash, the oauth ids, the primary key) is dropped and warned, never
written, even if you list it. That's why adding a column to your model never silently becomes a
privilege-escalation path at signup. The unsafe move isn't available, by construction.

## Where to go next

- These run on OAuth signup too: [Sign in with Google](sign-in-with-google.md).
- Adopt a schema you already have: [Onboard an existing users table](existing-users-table.md).
- The full reference: the [registration guide](../guides/accounts/registration.md#setting-columns-the-server-controls) and [Provisioning](../api/provisioning.md).
