# nomadproxy

An mTLS-escaping Nomad Proxy that exposes the Nomad API to your Tailscale
Tailnet.

## Build

```shell
go build -v -o nomadproxy ./nomadproxy.go
```

## Run

### Static auth key

If `TS_AUTH_KEY` is present in the environment, this takes precedence for
authenticating the proxy.

```shell
export TS_AUTH_KEY='...'

./nomadproxy \
  --hostname="nomad" \
  --backend-addr="https://nomad/ui"
```

### OAuth client

If OAuth client credentials are provided, a short-lived auth key will be
created for authenticating the proxy when/as needed. The tag(s) associated
with the OAuth client (and subsequent device auth key) can be supplied via
`--device-tag`.

```shell
export TAILNET_NAME='...'
export TS_OAUTH_CLIENT_ID='...'
export TS_OAUTH_CLIENT_SECRET='...'

./nomadproxy \
  --hostname="nomad" \
  --backend-addr="https://nomad/ui" \
  --device-tag='tag:nomad'
```