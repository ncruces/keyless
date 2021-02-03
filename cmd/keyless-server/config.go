package main

import (
	"encoding/json"
	"os"
)

var config struct {
	Domain      string `json:"domain"`
	CertHandler string `json:"cert_handler"`
	SignHandler string `json:"sign_handler"`

	Certificate string `json:"certificate"`
	MasterKey   string `json:"master_key"`
	LegacyKeys  string `json:"legacy_keys"`

	Cloudflare struct {
		Zone   string `json:"zone"`
		Token  string `json:"token"`
		Cert   string `json:"origin_cert"`
		Key    string `json:"origin_key"`
		PullCA string `json:"origin_pull_ca"`
	} `json:"cloudflare"`

	LetsEncrypt struct {
		API        string `json:"api"`
		Email      string `json:"email"`
		Account    string `json:"account_cfg"`
		AccountKey string `json:"account_key"`
	} `json:"letsencrypt"`
}

func loadConfig() error {
	f, err := os.Open("config.json")
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(&config)
}
