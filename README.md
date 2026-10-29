# oidc-iam

CLI token helper for [INDIGO IAM](https://indigo-iam.github.io/v/v1.14.0/) (1.14.x), without Homebrew `oidc-agent`. Each account is a JSON file in `~/.config/oidc-iam/`.

## Build

```bash
go build -o oidc ./cmd/oidc
# optional: go install ./cmd/oidc
```

## Account file

Path: `~/.config/oidc-iam/<name>.json` (mode `600` recommended). See `examples/wlcg.json.example`.

Register a client with **device code** and **refresh_token** grants and **`offline_access`** in scope. See [INDIGO IAM client registration](https://indigo-iam.github.io/v/v1.14.1/docs/tasks/user/client-registration/).

## Usage

```bash
oidc register myaccount https://iam.example.org/ CLIENT_ID CLIENT_SECRET
oidc register myaccount https://iam.example.org/ CLIENT_ID CLIENT_SECRET openid wlcg offline_access

oidc login myaccount
oidc token myaccount

curl -H "Authorization: Bearer $(oidc token myaccount)" https://api.example/resource
```

`oidc token` refreshes when the access token is missing or expires within **60 seconds**, or when the refresh token JWT `exp` is within **5 minutes**.

Override the config directory with `OIDC_IAM_CONFIG_DIR`.

## Project layout

```
cmd/oidc/          main binary
internal/account/  account JSON load/save
internal/config/   config directory resolution
internal/iam/      OIDC discovery, device flow, refresh
internal/jwt/      JWT exp helper
examples/          sample account JSON
```

## Raw curl (INDIGO IAM 1.14)

Discover endpoints:

```bash
ISSUER='https://iam.example.org/'
curl -sS "${ISSUER}.well-known/openid-configuration" \
  | jq -r '.token_endpoint, .device_authorization_endpoint'
```

Refresh token:

```bash
curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d grant_type=refresh_token \
  -d refresh_token="${REFRESH_TOKEN}" \
  "${TOKEN_ENDPOINT}"
```

Device code start and poll:

```bash
curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d client_id="${CLIENT_ID}" -d scope="${SCOPE}" \
  "${DEVICE_AUTHORIZATION_ENDPOINT}"

curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d device_code="${DEVICE_CODE}" \
  "${TOKEN_ENDPOINT}"
```
