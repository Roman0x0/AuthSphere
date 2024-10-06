package main

import (
	"encoding/json"
	"os"
)

type Settings struct {
	SiteName      string
	SiteNameFirst string
	SiteNameLast  string

	SessionSecret string
	CSRFSecret    string
	CaptchaSecret string
	SessionName   string
	SessionFlag   string

	DBLogin      string
	DBPass       string
	DBConnection string
	DBName       string

	ErrorColor  string
	GreenColor  string
	YellowColor string

	EmailBlockList string
	FromEmail      string
	SMTPPass       string
	ProjectName    string
	SMTPHost       string // smtp.zoho.eu
	SMTPPort       string // 587

	DomainName string
}

var (
	settings      Settings
	emailsToBlock []string
)

func LoadSettings() {
	file, _ := os.Open("settings.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	err := decoder.Decode(&settings)
	if err != nil {
		panic(err)
	}

	emailsToBlock = GetDisposableEmailList()
}
