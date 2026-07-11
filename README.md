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
Vaultwarden's RSA public key, the issuer has to match `KC_JWT_ISSUER` and `exp`/`nbf`
must be valid. The user is identified by the `sub` claim, so a token can only ever
read or write its own key.

## Configuration

Everything is set via environment variables, see [`.env.example`](.env.example):

- `KC_BIND_ADDR` (default `0.0.0.0:8081`)
- `KC_DATABASE_URL` (default `sqlite://keyconnector.db?mode=rwc`)
- `KC_JWT_ISSUER` (required), e.g. `https://vault.example.com|login`
- `KC_IDENTITY_PUBLIC_KEY_PATH` or `KC_IDENTITY_PUBLIC_KEY_PEM` (required)
- `KC_ENCRYPTION_KEY_PATH` or `KC_ENCRYPTION_KEY` (required), a base64 encoded
  32 byte key used to encrypt the stored keys at rest; generate one with
  `openssl rand -base64 32`

Vaultwarden generates an RSA keypair on first start (`data/rsa_key.pem` by default).
Export the public half for the connector:

```sh
openssl rsa -in /path/to/vaultwarden/data/rsa_key.pem -pubout -out identity.pub.pem
```

## Build, test, run

```sh
cargo test
cargo build --release
KC_JWT_ISSUER='https://vault.example.com|login' \
KC_IDENTITY_PUBLIC_KEY_PATH=./identity.pub.pem \
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
