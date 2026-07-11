# Key Connector protocol notes

This describes the key connector protocol as observed from the open source Vaultwarden
and Bitwarden client code. Bitwarden's own key-connector repository (and the
`bitwarden_license/` directories in the client and server repos) were not read or used
for this, the behaviour below is inferred from what the clients require of a connector.

## Sources

| Source | License | What was learned |
| ------ | ------- | ---------------- |
| `bitwarden/clients`, `libs/**` only | GPL-3.0 | The HTTP calls the client makes to a key connector, request/response bodies, auth header, the discovery flow via `UserDecryptionOptions`. |
| `dani-garcia/vaultwarden`, `src/**` | AGPL-3.0 | The JWT the identity provider issues (RS256, issuer, claims) that the connector has to validate. |

References (file : symbol):

- `clients/libs/common/src/services/api.service.ts` : `getMasterKeyFromKeyConnector`, `postUserKeyToKeyConnector`, `getKeyConnectorAlive`
- `clients/libs/common/src/key-management/key-connector/services/key-connector.service.ts` : `setMasterKeyFromUrl`, `migrateUser`, `convertNewSsoUserToKeyConnectorV1`
- `clients/libs/common/src/key-management/key-connector/models/key-connector-user-key.request.ts`
- `clients/libs/common/src/auth/models/response/key-connector-user-key.response.ts`
- `clients/libs/common/src/auth/models/response/user-decryption-options/*.ts`
- `vaultwarden/src/auth.rs` : `LoginJwtClaims`, `encode_jwt`, `JWT_LOGIN_ISSUER`, `initialize_keys`

## What the key connector is

A dumb, zero-knowledge key escrow. For SSO organizations with key connector enabled,
the user has no master password. Instead the user's master key (a 32 byte symmetric
key) is stored on a self-hosted key connector that the organization controls. At unlock
time the client fetches that key over an authenticated channel instead of deriving it
from a password.

The connector never sees vault data and never sees a password. It stores one opaque
base64 blob per user, addressed by the user's identity, and hands it back only to a
caller with a valid access token for that same identity.

## HTTP API

Base URL is the configured `keyConnectorUrl` of the org, paths are appended directly.

### `GET /alive`

No authentication. `200 OK` means the connector is healthy, used for reachability
checks.

### `GET /user-keys`

- Header `Authorization: Bearer <access_token>` (the identity access token).
- Header `Accept: application/json`.
- `200 OK` with body:
  ```json
  { "key": "<base64 of the user's 32 byte master key>" }
  ```
  The client reads the `key` property case-insensitively, camelCase is fine.
- Any non-200 is treated as a key connector error by the client, which then logs the
  user out.

### `POST /user-keys`

- Headers `Authorization: Bearer <access_token>`, `Content-Type: application/json; charset=utf-8`.
- Body:
  ```json
  { "key": "<base64 of the user's 32 byte master key>" }
  ```
- Stores or overwrites the key for the authenticated user, `200 OK` on success.

That is the entire connector surface the clients need: `GET /alive`, `GET /user-keys`,
`POST /user-keys`.

## Authentication

The bearer token is the standard access token issued by the identity provider
(Vaultwarden here). The connector has to:

1. Verify the signature. Vaultwarden signs with RS256 using a 2048 bit RSA key
   (`auth.rs::initialize_keys`, `JWT_ALGORITHM = RS256`), so validate against
   Vaultwarden's RSA public key.
2. Verify the issuer, which is `"<domain_origin>|login"` (`JWT_LOGIN_ISSUER`).
3. Verify `exp` and `nbf` (Vaultwarden uses 30s leeway).
4. Take the user from the `sub` claim (the user's GUID). This is the storage key.

A token only ever grants access to its own `sub`'s key, there is no cross-user access,
so no extra ACL is needed at the connector. Which users belong to a key connector org
is enforced upstream by the identity provider.

The relevant `LoginJwtClaims` fields (`auth.rs`): `nbf, exp, iss, sub, email, name,
email_verified, sstamp, device, scope: ["api","offline_access"], amr`.

## Discovery

On login (`connect/token`) the identity provider returns a `UserDecryptionOptions`
object. For a key connector user it contains:

```json
{
  "HasMasterPassword": false,
  "KeyConnectorOption": { "KeyConnectorUrl": "https://keyconnector.example.com" }
}
```

(`user-decryption-options.response.ts`, `key-connector-user-decryption-option.response.ts`)

- Existing key connector user, unlock: the client calls `GET {url}/user-keys`, base64
  decodes `key` into a `SymmetricCryptoKey` and uses it as the master key
  (`key-connector.service.ts::setMasterKeyFromUrl`).
- New SSO user being converted (V1): the client generates a random 512 bit secret, runs
  the org KDF to produce a master key, `POST {url}/user-keys` with the master key, then
  tells the main API via `POST /accounts/set-key-connector-key`
  (`convertNewSsoUserToKeyConnectorV1`).
- Existing password user migrating: `POST {url}/user-keys` with the current master key,
  then `POST /accounts/convert-to-key-connector` (`migrateUser`).

## Server-side endpoints the client also calls

These live on the main API (Vaultwarden), not on the connector:

| Method and path | Body | Purpose |
| --------------- | ---- | ------- |
| `POST /accounts/set-key-connector-key` | `key`, `keys` {pub/priv}, `kdf`, `kdfIterations`, `kdfMemory?`, `kdfParallelism?`, `orgIdentifier` | Finish converting a new SSO user. |
| `POST /accounts/convert-to-key-connector` | none | Mark an existing user as migrated. |
| `GET /accounts/key-connector/confirmation-details/{orgSsoIdentifier}` | none | Returns `{ OrganizationName }` for the domain confirmation UI. |

Plus the data the client reads from sync/profile: `organization.keyConnectorEnabled`,
`organization.keyConnectorUrl`, `user.usesKeyConnector`.

## Key material

The stored blob is the user's master key, the 32 byte symmetric key that wraps the
user key. In `convertNewSsoUserToKeyConnectorV1` a random 512 bit secret is fed through
the org KDF (`makeMasterKey`) to produce the master key, and
`Utils.fromBufferToB64(masterKey.inner().encryptionKey)` is what gets POSTed. The
connector treats it as an opaque base64 string and never parses or uses it.
