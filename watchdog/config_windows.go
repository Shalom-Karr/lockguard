//go:build windows && amd64

// config_windows.go — load lockguard.json (printer SSID, etc.).

package main

import (
	"encoding/json"
	"os"
)

type lockguardConfig struct {
	PrinterSSID     string `json:"printer_ssid"`
	PrinterMode     string `json:"printer_mode"` // "wifi_direct" or "infrastructure"
	EnforceInterval int    `json:"enforce_interval_seconds"`
}

const configPath = `C:\ProgramData\Lockguard\config\lockguard.json`

func loadConfig() (lockguardConfig, error) {
	var cfg lockguardConfig
	b, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
