# OIDC browser login

Fleetsweeper supports the OpenID Connect Authorization Code flow so
browser users can sign in with their existing SSO provider (Google, Okta,
Keycloak, Dex, Auth0, GitHub via Dex, etc.) instead of pasting bearer
tokens. API clients continue to use bearer tokens; OIDC adds a parallel
auth path for humans.

## Endpoints

| Path | Description |
| --- | --- |
| `/oidc/login` | Initiates the authorization code dance. Sets a short-lived state cookie and redirects to the IdP authorize endpoint. |
| `/oidc/callback` | Receives the authorisation code, exchanges it for an id_token, verifies the signature against the IdP's JWKS, derives the user's role, and sets a signed session cookie. |
| `/oidc/logout` | Clears the session cookie and redirects home. |

## Enable

Required configuration (CLI or env):

```yaml
oidc-issuer-url: "https://accounts.google.com"
oidc-client-id: "fleetsweeper-prod.apps.googleusercontent.com"
oidc-client-secret: "<from-idp>"
oidc-redirect-url: "https://fleetsweeper.example.com/oidc/callback"
session-secret: "<32-byte random hex>"
```

Optional claim mapping (the IdP-side claim name and value that grants each
role):

```yaml
oidc-admin-claim: "groups:fleetsweeper-admins"
oidc-operator-claim: "groups:fleetsweeper-operators"
oidc-default-role: "viewer"
```

Helm (recommended for production):

```yaml
oidc:
  enabled: true
  issuerURL: "https://accounts.google.com"
  clientID: "..."
  redirectURL: "https://fleetsweeper.example.com/oidc/callback"
  adminClaim: "groups:fleetsweeper-admins"
  operatorClaim: "groups:fleetsweeper-operators"
  existingSecret: fleetsweeper-oidc   # contains client-secret + session-secret
```

The chart wires both secrets into the Deployment as env vars and adds
`--oidc-*` arguments to the binary.

## How the role is decided

On every callback the server reads the verified ID token's claims and
checks them against the configured patterns in this order:

1. `oidc-admin-claim`. Sets role to `admin`.
2. `oidc-operator-claim`. Sets role to `operator`.
3. Otherwise. Sets role to `oidc-default-role` (default `viewer`).

Claim patterns are `<claim>:<value>`. The claim value may be a string or a
JSON array; the server tests membership in both shapes. Examples:

- `email:ops@example.com`. Promote a single user.
- `groups:fleetsweeper-admins`. Promote a group via an OIDC groups claim
  (when your IdP includes one).
- `hd:example.com`. Restrict by Google Workspace hosted domain.

## Cluster scope under OIDC

The current implementation grants the wildcard cluster scope (`*`) to
every OIDC session. Per-user cluster scope mapping is on the roadmap; in
the meantime, use API keys for pipelines that need narrowed scope.

## Cookie security

- The session cookie is signed with HMAC-SHA256 against `session-secret`.
- The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when the request
  arrives over TLS.
- The default lifetime is 8 hours (configurable via `--session-lifetime`).
- The cookie is stateless: it carries the subject and role, signed. No
  server-side session storage is required, which keeps fleetsweeper
  horizontally scalable.

## Logout

`POST /oidc/logout` (or simply visit `/oidc/logout`) clears the session
cookie. The IdP-side session is unaffected. Call your provider's logout
URL too if you need full sign-out.

## Troubleshooting

- **"state mismatch"** on callback: the user closed the tab and re-tried,
  or your reverse proxy stripped cookies. Make sure the proxy preserves
  `Set-Cookie` headers.
- **"id_token invalid"**: clock skew between fleetsweeper and the IdP. The
  `go-oidc` verifier allows 30 seconds; if your hosts drift more than that
  the verification fails. Sync to NTP.
- **"missing id_token in response"**: the IdP returned an OAuth2 access
  token but no ID token. Verify `oidc-scopes` includes `openid`.
