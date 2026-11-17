# Local JWT generator

Run from this directory:

```powershell
go run .
```

The command prints a `Bearer` token for `mock-customer` with the `Client User` role and a 10-minute lifetime.

```powershell
go run . -username alice -role 'Client User' -ttl 30m
```

The secret is read from `.env`, which is intentionally ignored by Git.
