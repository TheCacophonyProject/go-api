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
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	goconfig "github.com/TheCacophonyProject/go-config"
	"github.com/spf13/afero"
)

const (
	hostnameFile    = "/etc/hostname"
	hostsFile       = "/etc/hosts"
	hostsFileFormat = "127.0.0.1\t%s"
)

type Config struct {
	ServerURL      string
	Group          string
	DeviceName     string
	DevicePassword string
	DeviceID       int
	configRW       *goconfig.Config
}

func NewConfig(configFolder string) (*Config, error) {
	configRW, err := goconfig.New(configFolder)
	if err != nil {
		return nil, err
	}
	return &Config{
		configRW: configRW,
	}, nil
}

func (c *Config) Registered() bool {
	return c.DeviceID != 0
}

func (c *Config) read() error {
	var deviceConf goconfig.Device
	if err := c.configRW.Unmarshal(goconfig.DeviceKey, &deviceConf); err != nil {
		return err
	}

	var secretsConf goconfig.Secrets
	if err := c.configRW.Unmarshal(goconfig.SecretsKey, &secretsConf); err != nil {
		return err
	}

	c.ServerURL = deviceConf.Server
	c.Group = deviceConf.Group
	c.DeviceName = deviceConf.Name
	c.DevicePassword = secretsConf.DevicePassword
	c.DeviceID = deviceConf.ID
	if err := c.validate(); err != nil {
		return err
	}
	return nil
}

func (c *Config) write() error {
	if err := c.validate(); err != nil {
		return err
	}
	var d goconfig.Device
	if err := c.configRW.Unmarshal(goconfig.DeviceKey, &d); err != nil {
		return err
	}
	d.Group = c.Group
	d.ID = c.DeviceID
	d.Name = c.DeviceName
	d.Server = c.ServerURL
	if err := c.configRW.Set(goconfig.DeviceKey, &d); err != nil {
		return err
	}

	var s goconfig.Secrets
	if err := c.configRW.Unmarshal(goconfig.SecretsKey, &s); err != nil {
		return err
	}
	s.DevicePassword = c.DevicePassword
	return c.configRW.Set(goconfig.SecretsKey, &s)
}

func (c *Config) validate() error {
	// Not registere is a valid state
	valsNotSet := []string{}
	if c.ServerURL == "" {
		valsNotSet = append(valsNotSet, "server url is not set")
	}

	if c.DeviceID == 0 {
		valsNotSet = append(valsNotSet, "device id is not set")
	}

	if c.DevicePassword == "" {
		valsNotSet = append(valsNotSet, "device password is not set")
	}
	if c.Group == "" {
		valsNotSet = append(valsNotSet, "device group is not set")
	}
	if c.DeviceName == "" {
		valsNotSet = append(valsNotSet, "device name is not set")
	}

	if len(valsNotSet) == 0 || len(valsNotSet) == 5 {
		return nil // Not registered (nothing set in config) is a valid state
	}

	return fmt.Errorf("error with config. %s", strings.Join(valsNotSet, ", "))
}

func safeName(name string) string {
	name = strings.ToLower(name)
	reg := regexp.MustCompile("[^a-z0-9]+")
	return reg.ReplaceAllString(name, "")
}

func updateHostnameAndSaltGrains(device *CacophonyDevice) error {
	// Write the new hostname.
	if err := afero.WriteFile(Fs, hostnameFile, []byte(device.hostname()), 0644); err != nil {
		return err
	}

	input, err := afero.ReadFile(Fs, hostsFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(input), "\n")

	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] == "127.0.0.1" {
			lines[i] = fmt.Sprintf(hostsFileFormat, device.hostname())
		}
	}
	output := strings.Join(lines, "\n")
	err = afero.WriteFile(Fs, hostsFile, []byte(output), 0644)
	if err != nil {
		return err
	}

	// Write the new salt grains.
	newGrains := map[string]string{
		"device_name": device.name,
		"group":       device.group,
	}

	// Convert the map to JSON
	grainsJSON, err := json.Marshal(newGrains)
	if err != nil {
		return err
	}

	out, err := setSaltGrains(string(grainsJSON))
	if err != nil {
		log.Println(string(out))
		return err
	}
	return nil
}

// setSaltGrains is a wrapper around the salt-call grains.setvals command. This is done for testing purposes
var setSaltGrains = func(grains string) ([]byte, error) {
	return exec.Command("salt-call", "grains.setvals", grains).CombinedOutput()
}

var Fs = afero.NewOsFs()
