
package api

import (
	"fmt"
	"path/filepath"
	"strings"
)

func Open(configFile string) (*CacophonyAPI, error) {
	// TODO(mjs) - much of this is copied straight from
	// thermal-uploader and should be extracted.
	conf, err := ParseConfigFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("configuration error: %v", err)
	}
	privConfigFilename := privConfigFilename(configFile)
	password, err := ReadPassword(privConfigFilename)
	if err != nil {
		return nil, err
	}

	api, err := NewAPI(conf.ServerURL, conf.Group, conf.DeviceName, password)
	if err != nil {
		return nil, err
	}

	// TODO(mjs) - there's a race here if both thermal-uploader and
	// event-reporter register at about the same time. Extract this to
	// a library which does locking.
	if api.JustRegistered() {
		err := WritePassword(privConfigFilename, api.Password())
		if err != nil {
			return nil, err
		}
	}

	return api, nil
}

func privConfigFilename(configFile string) string {
	dirname, filename := filepath.Split(configFile)
	bareFilename := strings.TrimSuffix(filename, ".yaml")
	return filepath.Join(dirname, bareFilename+"-priv.yaml")
}