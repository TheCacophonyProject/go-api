// go-api - Client for the Cacophony API server.
// Copyright (C) 2018, The Cacophony Project
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package api

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
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

//Validate checks supplied Config contains the required data
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
	return nil
}

//ParseConfig takes supplied filename and returns a parsed Config struct
func ParseConfigFile(filename string) (*Config, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseConfig(buf)
}

//ParseConfig takes supplied bytes and returns a parsed Config struct
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

//ReadPassword reads the password from supplied filename location
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

// WritePassword takes a filename and password. Locks the file (OS-level) and
// writes the supplied password to the file
func WritePassword(filename, password string) error {
	conf := PrivateConfig{Password: password}
	buf, err := yaml.Marshal(&conf)
	if err != nil {
		return err
	}

	fileLock := flock.New(filename)
	lockCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	locked, err := fileLock.TryLockContext(lockCtx, 678*time.Millisecond)
	if err != nil {
		return err
	}
	if locked {
		err = ioutil.WriteFile(filename, buf, 0600)
		fileLock.Unlock()
	} else {
		return fmt.Errorf("WritePassword could not get file lock %v", filename)
	}
	return err
}

// privCOnfigFileName take a configFile and creates an associated
// file to store the password in with suffix -priv.yaml
func privConfigFilename(configFile string) string {
	dirname, filename := filepath.Split(configFile)
	bareFilename := strings.TrimSuffix(filename, ".yaml")
	return filepath.Join(dirname, bareFilename+"-priv.yaml")
}
