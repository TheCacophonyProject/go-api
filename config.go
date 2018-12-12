
package api

import (
	"errors"
	"io/ioutil"
	"os"
	"fmt"
	"path/filepath"
	"strings"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	ServerURL  string `yaml:"server-url"`
	Group      string `yaml:"group"`
	DeviceName string `yaml:"device-name"`
}

type PrivateConfig struct {
	Password string `yaml:"password"`
}

func (conf *Config) Validate() error {
	if conf.ServerURL == "" {
		return errors.New("server-url missing")
	}
	if conf.Group == "" {
		return errors.New("group missing")
	}
	if conf.DeviceName == "" {
		return errors.New("device-name missing")
	}
	if conf.Directory == "" {
		return errors.New("directory missing")
	}
	return nil
}

func ParseConfigFile(filename string) (*Config, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseConfig(buf)
}

func ParseConfig(buf []byte) (*Config, error) {
	conf := &Config{}

	if err := yaml.Unmarshal(buf, conf); err != nil {
		return nil, err
	}
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	return conf, nil
}

func ReadPassword(filename string) (string, error) {
	buf, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	var conf PrivateConfig
	if err := yaml.Unmarshal(buf, &conf); err != nil {
		return "", err
	}
	return conf.Password, nil
}

func WritePassword(filename, password string) error {
	conf := PrivateConfig{Password: password}
	buf, err := yaml.Marshal(&conf)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, buf, 0600)
}

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