# Storage

The server-side store for sessions, CSRF tokens, and one-time tokens. Pick a backend with
`get_session_storage(...)`, or implement `AbstractSessionStorage` for your own.

::: crudauth.storage.AbstractSessionStorage

::: crudauth.storage.MemorySessionStorage

::: crudauth.storage.RedisSessionStorage

::: crudauth.storage.get_session_storage
