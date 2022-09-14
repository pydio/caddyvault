package caddyvault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/pydio/caddyvault/utils"
)

const (
	defaultPrefix = "caddycerts"

	dataURL = "data"
	metaURL = "metadata"
)

// VaultStorage is a certmagic.Storage implementation for storing for ACME certificates
// inside an Hashicorp Vault server.
type VaultStorage struct {
	// API is the vault server address, including scheme, host and port. If it is empty, module looks up for VAULT_ADDR env variable.
	API string
	// Prefix is the vault server store path. A secret engine **v2** must be created at this path. Defaults to 'caddycerts'.
	Prefix string
	// Token should generally be passed via the VAULT_TOKEN env variable, but can be set manually here.
	Token string
}

func (vs *VaultStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.vault",
		New: func() caddy.Module {
			return vs
		},
	}
}

func init() {
	caddy.RegisterModule(&VaultStorage{})
}

func (vs *VaultStorage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		key := d.Val()
		var value string

		if !d.Args(&value) {
			continue
		}

		switch key {
		case "address":
			if value != "" {
				vs.API = value
			}
		case "store":
			if value != "" {
				vs.Prefix = value
			}
		case "token":
			if value != "" {
				utils.Token = value
			}
		}
	}
	if vs.API == "" {
		if a := os.Getenv("VAULT_ADDR"); a != "" {
			vs.API = a
		} else {
			return fmt.Errorf("unable to find Vault address. Make sure to define it in Caddyfile or in VAULT_ADDR env")
		}
	}
	if utils.Token == "" && os.Getenv("VAULT_TOKEN") == "" {
		return fmt.Errorf("unable to find Vault token. Make sure to define it in Caddyfile or in VAULT_TOKEN env")
	}
	return nil
}

func (vs *VaultStorage) Provision(ctx caddy.Context) error {
	return nil
}

// CertMagicStorage converts vs to a certmagic.Storage instance.
func (vs *VaultStorage) CertMagicStorage() (certmagic.Storage, error) {
	return vs, nil
}

func (vs *VaultStorage) buildURL(u string, key ...string) string {
	pref := vs.Prefix
	if pref == "" {
		pref = defaultPrefix
	}
	ur := vs.API + "/v1/" + pref + "/" + u + "/"
	if len(key) > 0 {
		ur += key[0]
	}
	return ur
}

// List lists certificates
func (vs *VaultStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var list []string
	if recursive {
		list = listPath(vs.buildURL(metaURL), vs.buildURL(dataURL), prefix)
	} else {
		list = queryPath(vs.buildURL(dataURL), prefix)
	}

	if len(list) == 0 {
		return list, os.ErrNotExist
	}
	return list, nil
}

// Load retrieves certificate of key
func (vs *VaultStorage) Load(ctx context.Context, key string) ([]byte, error) {
	res := utils.QueryStore(vs.buildURL(dataURL, key))
	if len(res.Data.Data) == 0 {
		return []byte{}, os.ErrNotExist
	}
	return []byte(res.Data.Data[key].(string)), nil
}

// Store stores certificate with key association
func (vs *VaultStorage) Store(ctx context.Context, key string, value []byte) error {
	data := make(map[string]string)
	data[key] = string(value)
	req := &utils.Request{
		Data: data,
	}
	byteData, _ := json.Marshal(req)
	response, err := utils.LoadStore(vs.buildURL(dataURL, key), byteData)
	if len(response.Errors) > 0 {
		return errors.New("Failed to store, error: " + response.Errors[0])
	}
	return err
}

// Exists returns existance of certificate with key
func (vs *VaultStorage) Exists(ctx context.Context, key string) bool {
	res := utils.QueryStore(vs.buildURL(dataURL, key))
	return len(res.Data.Data) > 0 && !res.Data.Metadata.Destroyed
}

// Stat retrieves status of certificate with key param
func (vs *VaultStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	res := utils.QueryStore(vs.buildURL(dataURL, key))
	_, err := vs.List(ctx, key, false)
	modified, merror := time.Parse(time.RFC3339, res.Data.Metadata.CreatedTime)
	return certmagic.KeyInfo{
		Key:        key,
		IsTerminal: err == os.ErrNotExist,
		Size:       int64(len(res.Data.Data[key].(string))),
		Modified:   modified,
	}, merror
}

/*
Util functions start here
listPath and queryPath
*/

func listPath(listurl, loadurl, prefix string) []string {
	var list []string
	var res utils.Result

	// list all the keys
	list = append(list, queryPath(loadurl, prefix)...)

	// list all the paths and loop keys
	res = utils.ListStore(listurl + prefix)
	for _, path := range res.Data.Keys {
		list = append(list, listPath(listurl+prefix, loadurl+prefix, "/"+path)...)
	}
	return list
}

func queryPath(url, prefix string) []string {
	var res utils.Result
	var list []string
	res = utils.QueryStore(url + prefix)
	for item := range res.Data.Data {
		list = append(list, item)
	}
	return list
}

// Lock locks operations on certificate with particular key
func (vs *VaultStorage) Lock(c context.Context, key string) error {
	key = key + ".lock"

	if vs.Exists(c, key) {

		if stat, err := vs.Stat(c, key); err == nil {

			// check for deadlock, wait for 5 (300s) minutes
			if time.Now().Unix()-stat.Modified.Unix() > 60 {
				_ = vs.Unlock(c, key)
			} else {
				return errors.New("Lock already exists")
			}
		} else {
			return err
		}
	}

	return lockSystem(key, vs.buildURL(dataURL, key))
}

// Unlock unlocks operations on certificate data
func (vs *VaultStorage) Unlock(ctx context.Context, key string) error {
	if strings.Index(key, ".lock") < 0 {
		key = key + ".lock"
	}
	return vs.Delete(ctx, key)
}

// Delete deletes the certificate from vault.
func (vs *VaultStorage) Delete(ctx context.Context, key string) error {
	response, err := utils.DeleteStore(vs.buildURL(metaURL, key))
	if len(response.Errors) > 0 {
		return errors.New("Failed to delete" + response.Errors[0])
	}
	return err
}

func lockSystem(key, lockPath string) error {
	data := make(map[string]string)
	data[key] = "locked"
	postBody := utils.Request{
		Options: utils.Options{
			Cas: 0,
		},
		Data: data,
	}
	jsonData, _ := json.Marshal(postBody)
	response, err := utils.LoadStore(lockPath, jsonData)
	if len(response.Errors) > 0 {
		return errors.New("Failed to lock: " + response.Errors[0])
	}
	return err
}
