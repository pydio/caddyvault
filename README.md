# CaddyVault

A Storage plugin for CaddyServer V2 using [Vault](https://vaultproject.io) as backend for storing TLS data like certificates, keys etc.,
This is a fork from [https://github.com/siva-chegondi/caddyvault](https://github.com/siva-chegondi/caddyvault) who initially wrote the Caddy V1 version.

## Prerequisite
This plugin expects the following environment. 
* A VAULT server running and accessible from the machine/s on which caddy is running.
* A KV secret engine **version 2** on the path _caddycerts_: `vault secrets enable -version=2 -path=caddycerts kv`
* A VAULT_TOKEN set in the environment variable

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
* Enable this storage in the Caddyfile using
```
{
  storage vault {
    address https://localhost:8200     # can be passed via VAULT_ADDR as well
    prefix caddycerts                  # store name, defaults to caddycerts
    token   xxx                        # [optional if not set via VAULT_TOKEN env]
  }
}
```