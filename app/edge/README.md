# Apex Scanner — TLS edge proxy rollout

FQDN: **apexscanner.6dcorp.internal** · single HTTPS origin · cert from Vault PKI, auto-renewed by Vault Agent.

> Deploy only after Phase-0 prereqs: DNS A record, CA cert at `/opt/vault/cert/6d-corp.pem`,
> real AppRole `role_id`/`secret_id`, and host `:80`/`:443` free.

## Files in this dir
- `nginx.conf` — the edge proxy config (mounted read-only into the container).
- `../docker-compose.edge.yml` — overlay that adds the `edge` service + sets `CORS_ORIGINS`.

## 1. Validate issuance (throwaway test)
```bash
export VAULT_ADDR="https://vault.6dcorp.internal"
export VAULT_CACERT="/opt/vault/cert/6d-corp.pem"
export VAULT_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="<OURS>" secret_id="<OURS>")
vault write -format=json pki_int/issue/6dcorp-internal \
  common_name="apexscanner.6dcorp.internal" ttl=720h | jq -e '.data.certificate' >/dev/null && echo OK
```

## 2. Vault Agent — render ONE combined PEM (cert chain + key)
nginx can read both `ssl_certificate` and `ssl_certificate_key` from the same
file, so we render a single PEM. This is important: splitting cert and key into
two Agent templates issues the cert **twice** (each `{{ secret "pki_int/issue…" }}`
is its own write) → the key won't match the cert → nginx rejects it. One template
= one issuance = always-matched pair. (This is the deployed setup.)

`/etc/vault-agent/combined.ctpl`:
```
{{ with secret "pki_int/issue/6dcorp-internal" "common_name=apexscanner.6dcorp.internal" "ttl=720h" }}
{{ .Data.certificate }}
{{ range .Data.ca_chain }}{{ . }}
{{ end }}{{ .Data.private_key }}
{{ end }}
```

`/etc/vault-agent/agent.hcl`:
```hcl
vault {
  address = "https://vault.6dcorp.internal"
  ca_cert = "/opt/vault/cert/6d-corp.pem"
}
auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/etc/vault-agent/role_id"
      secret_id_file_path = "/etc/vault-agent/secret_id"
    }
  }
}
template {
  source      = "/etc/vault-agent/combined.ctpl"
  destination = "/etc/ssl/apexscanner/combined.pem"
  perms       = "0640"
  command     = "docker exec apexscanner_edge nginx -s reload"
}
```
The edge `nginx.conf` points both TLS directives at `combined.pem`.
Creds + dir:
```bash
install -d -m 700 /etc/vault-agent && install -d -m 755 /etc/ssl/apexscanner
printf '%s' "<OUR_ROLE_ID>"   > /etc/vault-agent/role_id
printf '%s' "<OUR_SECRET_ID>" > /etc/vault-agent/secret_id
chmod 600 /etc/vault-agent/role_id /etc/vault-agent/secret_id
```
Then install the `vault-agent.service` systemd unit (runbook §2d) and `enable --now`.
Confirm `/etc/ssl/apexscanner/combined.pem` exists before step 4.

## 3. Harden raw ports (one-line edits to ../docker-compose.yml)
So the edge is the only public entry, bind the raw ports to localhost:
```
dashboard: "127.0.0.1:${DASHBOARD_PORT:-3001}:8080"
api:       "127.0.0.1:7070:8000"
```
(Overlays append to `ports:`, so this is done in the base file, not the overlay.)

## 4. Rebuild frontend (same-origin) + bring up the edge
The frontend same-origin change (api.js / ScanResults getApiHost → `window.location.origin`)
is already in the source; rebuild so it ships, then start the edge:
```bash
docker-compose build dashboard
docker-compose -f docker-compose.yml -f docker-compose.edge.yml up -d
```

## 5. Verify
```bash
curl --cacert /opt/vault/cert/6d-corp.pem https://apexscanner.6dcorp.internal/health
curl -sI http://apexscanner.6dcorp.internal/ | grep -i location   # expect 301 -> https
```
Then in a browser: load the app over https, log in (cookie), run a scan, open a report
and an SBOM (both https, no mixed-content warning). `journalctl -u vault-agent -f`
should show login + render; force-renew to confirm nginx reloads.

## Rollback
`docker-compose -f docker-compose.yml -f docker-compose.edge.yml down` removes the edge;
revert the port-hardening lines and rebuild the dashboard to restore the two-port mode.
