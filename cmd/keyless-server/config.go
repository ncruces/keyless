package main

import (
	"encoding/json"
	"os"
	"strings"
)

var config struct {
	Domain     string `json:"domain"`
	Handler    string `json:"handler"`
	Nameserver string `json:"nameserver"`
	CName      string `json:"cname"`

	Certificate string `json:"certificate"`
	MasterKey   string `json:"master_key"`
	LegacyKeys  string `json:"legacy_keys"`

	Cloudflare struct {
		Cert   string `json:"origin_cert"`
		Key    string `json:"origin_key"`
		PullCA string `json:"origin_pull_ca"`
	} `json:"cloudflare"`

	LetsEncrypt struct {
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

	err = json.NewDecoder(f).Decode(&config)

	// set defaults
	config.Handler = strings.TrimSuffix(config.Handler, "/")
	if !strings.HasSuffix(config.Nameserver, ".") {
		config.Nameserver += "."
	}
	if config.CName != "" && !strings.HasSuffix(config.CName, ".") {
		config.CName += "."
	}

	return err
}
