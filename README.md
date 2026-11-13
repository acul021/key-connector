# key-connector

A small key connector for [Vaultwarden](https://github.com/dani-garcia/vaultwarden),
compatible with the Bitwarden clients.

For SSO organizations that use a key connector, users have no master password. The
master key is stored here instead and fetched by the client at unlock time. The service
never sees vault data or passwords, it just stores one opaque base64 blob per user,
addressed by the user id of a validated access token.

The protocol was worked out from the open source Vaultwarden (AGPL) and Bitwarden
client (GPL) code, see [docs/PROTOCOL.md](docs/PROTOCOL.md) for the details and
references. Bitwarden's own key-connector code was not used for this.

## API

| Method | Path         | Auth         | Body / Response                 |
| ------ | ------------ | ------------ | ------------------------------- |
| GET    | `/alive`     | none         | `200 OK` health check           |
| GET    | `/user-keys` | Bearer token | `200` with `{ "key": "<b64>" }` |
| POST   | `/user-keys` | Bearer token | `{ "key": "<b64>" }`, `200`     |

The bearer token is the Vaultwarden access token. It is verified with RS256 against
Vaultwarden's RSA public key, the issuer and `exp`/`nbf` must be valid. The user is
identified by the `sub` claim, so a token can only ever read or write its own key.

## Configuration

Everything is set via environment variables, see [`.env.example`](.env.example):

- `KC_BIND_ADDR` (default `0.0.0.0:8081`)
- `KC_DATABASE_URL`, see [Database](#database). The bare binary defaults to
  `sqlite://keyconnector.db?mode=rwc` in the working directory, the Docker image
  sets `sqlite:///data/keyconnector.db?mode=rwc`
- `KC_IDENTITY_AUTHORITY`, e.g. `https://vault.example.com/identity` — issuer and
  signing key are fetched from its OIDC discovery document and refreshed
  periodically, nothing else to configure
- alternatively a static key: `KC_IDENTITY_PUBLIC_KEY_PATH` or
  `KC_IDENTITY_PUBLIC_KEY_PEM`, plus `KC_JWT_ISSUER`
  (e.g. `https://vault.example.com|login`)
- `KC_ENCRYPTION_KEY_PATH` or `KC_ENCRYPTION_KEY` (required), a base64 encoded
  32 byte key used to encrypt the stored keys at rest; generate one with
  `openssl rand -base64 32`

With a static key, export the public half of the RSA keypair Vaultwarden generates
on first start (`data/rsa_key.pem` by default):

```sh
openssl rsa -in /path/to/vaultwarden/data/rsa_key.pem -pubout -out identity.pub.pem
```

## Database

SQLite and PostgreSQL are supported, picked by the URL scheme. Any other scheme is
rejected at startup.

```sh
# SQLite, relative to the working directory. mode=rwc creates the file on first start.
KC_DATABASE_URL='sqlite://keyconnector.db?mode=rwc'
# SQLite, absolute path (note the three slashes)
KC_DATABASE_URL='sqlite:///data/keyconnector.db?mode=rwc'
# PostgreSQL, postgres:// and postgresql:// both work
KC_DATABASE_URL='postgresql://keyconnector:secret@db.example.com:5432/keyconnector?sslmode=verify-full'
KC_DATABASE_URL='postgres://keyconnector:secret@db.internal/keyconnector?sslmode=require'
```

Percent-encode `@ : / # ? %` in the password, e.g. `#` as `%23`. A URL with a raw
`#` is rejected at startup.

The PostgreSQL URL parser in sqlx understands only these query parameters:
`sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `host`, `hostaddr`, `port`,
`dbname`, `user`, `password`, `application_name`, `options` and
`statement-cache-capacity`. Other libpq parameters such as `connect_timeout` or
`target_session_attrs` are ignored.

TLS behaves differently from libpq in places:

- Without `sslmode` the default is `prefer`, which falls back to plaintext without
  a warning if the server doesn't offer TLS. The `PG*` environment variables
  (`PGSSLMODE`, `PGHOST`, `PGPASSWORD` and so on) also apply and fill in
  whatever the URL leaves out, so `prefer` is only the default when
  `PGSSLMODE` is unset.
- `require` encrypts but never checks the server certificate, even with
  `sslrootcert` set. libpq would check it against the root certificate in that
  case.
- `verify-full` checks the certificate and the host name against the bundled
  Mozilla root certificates. `sslrootcert` adds a CA to those roots instead of
  replacing them, so a publicly trusted certificate for the database host name
  is accepted as well. libpq would trust only the given CA.
- `verify-ca` skips the host name check, and with the public roots still
  trusted that accepts any publicly trusted certificate. Use `verify-full`.
- `allow` behaves like `disable`.

So use `sslmode=verify-full` unless the network path to the database is trusted.

The table is created on first start, for both databases. On PostgreSQL this
needs the CREATE privilege on the schema, which PostgreSQL 15 and later no longer
grant on `public` by default. Either grant it for the first start, or create the
table beforehand:

```sql
CREATE TABLE user_keys (
    user_id TEXT PRIMARY KEY NOT NULL,
    key     TEXT NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON user_keys TO keyconnector;
```

After that, SELECT, INSERT and UPDATE on `user_keys` are all key-connector needs.

Without `mode=rwc` SQLite only opens an existing file. If the file or its directory
can't be created, startup fails with `(code: 14) unable to open database file`. If
the file or its directory exists but isn't writable, startup fails with `attempt to
write a readonly database`. key-connector checks this with a write that it rolls
back.

In Docker the database lives in the `/data` volume. The container runs as uid
10001, so a bind mount must be writable by that uid:

```sh
mkdir -p ./kc-data && sudo chown 10001 ./kc-data
docker run -v "$PWD/kc-data:/data" ... key-connector
```

Startup errors show a PostgreSQL URL as user, host, port, database name and
`sslmode` only, with the password replaced by `***`. A URL that can't be parsed
reliably is shown as its scheme only, or not at all.

## Vaultwarden setup

Key Connector support is not merged in Vaultwarden yet, see
[PR #7419](https://github.com/dani-garcia/vaultwarden/pull/7419). Until then the
`main` branch of [acul021/vaultwarden](https://github.com/acul021/vaultwarden) has
the PR included and is built as `ghcr.io/acul021/vaultwarden:testing` (amd64 only).

Vaultwarden needs working SSO, plus:

```ini
KEY_CONNECTOR_ENABLED=true
KEY_CONNECTOR_URL=https://keyconnector.example.com
# Shown on the enrollment confirmation screen in the clients:
KEY_CONNECTOR_ORG_NAME=Example Corp
```

New SSO users are then enrolled with the connector instead of being asked to create
a master password. Existing users are offered to remove their master password on
their next SSO login.

## Build, test, run

```sh
cargo test
cargo build --release
KC_IDENTITY_AUTHORITY='https://vault.example.com/identity' \
KC_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  ./target/release/key-connector
```

Or with Docker: `docker build -t key-connector .`

## Deployment notes

Run this behind a reverse proxy with TLS, the clients require an https connector URL
anyway and the access token and key would otherwise go over the wire in plain text.

The stored keys are encrypted at rest with AES-256-GCM under `KC_ENCRYPTION_KEY`,
each entry bound to its user id, so a leaked database or backup is useless on its
own. Plaintext rows from older versions are encrypted once at startup.

The encryption key is as critical as the database itself: losing either one locks
the affected users out of their vaults permanently. Back both up, and keep the key
away from the database and its backups, e.g. mounted from a secret store via
`KC_ENCRYPTION_KEY_PATH`. Keeping the database on a different host than the
Vaultwarden one is still a good idea.

## License

AGPL-3.0-or-later, same as Vaultwarden.
