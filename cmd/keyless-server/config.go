package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

var config struct {
	Domain     string `json:"domain"`
	Nameserver string `json:"nameserver"`
	CName      string `json:"cname"`

	Certificate string `json:"certificate"`
	MasterKey   string `json:"master_key"`
	LegacyKeys  string `json:"legacy_keys"`

	API struct {
		Handler     string `json:"handler"`
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
		ClientCA    string `json:"client_ca"`
	} `json:"api"`

	LetsEncrypt struct {
		Account    string `json:"account"`
		AccountKey string `json:"account_key"`
	} `json:"letsencrypt"`
}

func loadConfig() error {
	f, err := os.Open("config.json")
	if err != nil {
		return err
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&config); err != nil {
		return err
	}

	// check required fields
	if config.Domain == "" {
		return errors.New("domain is not configured")
	}
	if config.Nameserver == "" {
		return errors.New("nameserver is not configured")
	}
	if config.Certificate == "" {
		return errors.New("certificate file path is not configured")
	}
	if config.MasterKey == "" {
		return errors.New("master_key file path is not configured")
	}
	if config.API.Handler == "" {
		return errors.New("handler is not configured")
	}
	if config.LetsEncrypt.Account == "" {
		return errors.New("letsencrypt.account_cfg file path is not configured")
	}
	if config.LetsEncrypt.Account == "" {
		return errors.New("letsencrypt.account_key file path is not configured")
	}

	// set defaults
	if !strings.HasSuffix(config.Domain, ".") {
		config.Domain += "."
	}
	if !strings.HasSuffix(config.Nameserver, ".") {
		config.Nameserver += "."
	}
	if config.CName != "" && !strings.HasSuffix(config.CName, ".") {
		config.CName += "."
	}
	config.API.Handler = strings.TrimSuffix(config.API.Handler, "/")

	return nil
}
