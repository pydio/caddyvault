# CaddyVault

A Storage plugin for caddyserver V2 using [Vault](https://vaultproject.io) as backend for storing TLS data like certificates, keys etc.,

## Prerequisite
This plugin expects the following environment. 
* You need a VAULT server running and accessible from the machine/s on which caddy is running.
* Enabled KV2 secrets engine on the path _caddycert_: `vault secrets enable -version=2 -path=caddycerts kv`

## Compile Caddy v2 with CaddyVault plugin
To extend caddy with CaddyVault plugin, we need to include following `import statement`
in github.com/caddyserver/caddy/caddy/caddymain/run.go file.
```
import (
   _ "github.com/caddyserver/caddy/v2"
   _ "github.com/pydio/caddyvault"
)
```

## Configuration

### Vault configuration
* We need to enable KV2 secrets engine on the path `certpaths`.

### Caddy configuration
* We can enable `CaddyVault` plugin by setting environment variable `CADDY_CLUSTERING` to `vault`.
* Now set the following environment variables.
   
    * CADDY_CLUSTERING_VAULT_ENDPOINT
    * CADDY_CLUSTERING_VAULT_KEY
