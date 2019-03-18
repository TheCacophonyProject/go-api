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
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

// tests against cacophony-api require apiURL to be pointing
// to a valid cacophony-api server and test-seed.sql to be run

var apiURL = "http://localhost:1080"
var tokenSuccess = true
var responseHeader = http.StatusOK
var rawThermalData = randString(100)
var testConfig = "/var/tmp/go-api-test-config.yaml"

var defaultDevice = "test-device"
var defaultPassword = "test-password"
var defaultGroup = "test-group"
var testEventDetail = `{"description": {"type": "test-id", "details": {"tail":"fuzzy"} } }`
var tempPasswordFile = "/var/tmp/password.tmp"

//Tests against httptest

func TestRegistrationHttpRequest(t *testing.T) {
	ts := GetRegisterServer(t)
	defer ts.Close()
	api := getAPI(ts.URL, "", false)
	err := api.register()
	assert.Equal(t, nil, err)
}

func TestNewTokenHttpRequest(t *testing.T) {
	ts := GetNewAuthenticateServer(t)
	defer ts.Close()

	api := getAPI(ts.URL, "", true)
	err := api.authenticate()
	assert.Equal(t, err, nil)
}

func TestUploadThermalRawHttpRequest(t *testing.T) {
	ts := GetUploadThermalRawServer(t)
	defer ts.Close()

	api := getAPI(ts.URL, "", true)
	reader := strings.NewReader(rawThermalData)
	err := api.UploadThermalRaw(reader)
	assert.Equal(t, nil, err)
}

func getTokenResponse() *tokenResponse {
	return &tokenResponse{
		Messages: []string{},
		Token:    "tok-" + randString(20),
	}
}

func getJSONRequestMap(r *http.Request) map[string]string {
	var requestJson = map[string]string{}
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&requestJson)
	return requestJson
}

// GetRegisterServer returns a test server that checks that register posts contain
// password,group and devicename
func GetRegisterServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestJson := getJSONRequestMap(r)

		assert.Equal(t, http.MethodPost, r.Method)
		assert.NotEqual(t, "", requestJson["password"])
		assert.NotEqual(t, "", requestJson["group"])
		assert.NotEqual(t, "", requestJson["devicename"])

		w.WriteHeader(responseHeader)
		w.Header().Set("Content-Type", "application/json")
		token := getTokenResponse()
		json.NewEncoder(w).Encode(token)
	}))
	return ts
}

//GetNewAuthenticateServer returns a test server that checks that posts contains
// passowrd and devicename
func GetNewAuthenticateServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestJson := getJSONRequestMap(r)

		assert.Equal(t, http.MethodPost, r.Method)
		assert.NotEqual(t, "", requestJson["password"])
		assert.NotEqual(t, "", requestJson["devicename"])

		w.WriteHeader(responseHeader)
		w.Header().Set("Content-Type", "application/json")
		token := getTokenResponse()
		json.NewEncoder(w).Encode(token)
	}))
	return ts
}

//getMimeParts retrieves data and  file:file and Value:data from a multipart request
func getMimeParts(r *http.Request) (string, string) {
	partReader, err := r.MultipartReader()

	var fileData, dataType string
	form, err := partReader.ReadForm(1000)
	if err != nil {
		return "", ""
	}

	if val, ok := form.File["file"]; ok {
		filePart := val[0]
		file, _ := filePart.Open()
		b := make([]byte, 1)
		for {
			n, err := file.Read(b)
			fileData += string(b[:n])
			if err == io.EOF {
				break
			}
		}
	}

	if val, ok := form.Value["data"]; ok {
		dataType = val[0]
	}
	return dataType, fileData
}

//GetUploadThermalRawServer checks that the message is multipart and contains the required multipartmime file:file and Value:data
//and Authorization header
func GetUploadThermalRawServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.NotEqual(t, nil, r.Header.Get("Authorization"))

		dataType, file := getMimeParts(r)
		assert.Equal(t, "{\"type\":\"thermalRaw\"}", dataType)
		assert.Equal(t, rawThermalData, file)

		w.WriteHeader(responseHeader)
	}))
	return ts
}

//Tests against cacophony-api server running at apiURL

func TestAPIRegistration(t *testing.T) {
	api := getAPI(apiURL, "", false)
	err := api.authenticate()
	assert.NotEqual(t, nil, err)

	err = api.register()
	assert.Equal(t, nil, err)
	assert.True(t, api.JustRegistered())
	assert.NotEqual(t, "", api.device.password)
	assert.NotEqual(t, "", api.token)
	assert.True(t, api.JustRegistered())

	err = api.authenticate()
	assert.Equal(t, err, nil)
}

func TestAPIAuthenticate(t *testing.T) {
	api := getAPI(apiURL, defaultPassword, false)
	api.device.name = defaultDevice
	err := api.authenticate()
	assert.Equal(t, nil, err)
	assert.NotEqual(t, "", api.token)
}

func TestAPIUploadThermalRaw(t *testing.T) {
	api := getAPI(apiURL, "", false)
	err := api.register()

	reader := strings.NewReader(rawThermalData)
	err = api.UploadThermalRaw(reader)
	assert.Equal(t, nil, err)
}

func getTestEvent() ([]byte, []time.Time) {
	details := []byte(testEventDetail)
	timeStamps := []time.Time{time.Now()}
	return details, timeStamps
}

func TestAPIReportEvent(t *testing.T) {
	api := getAPI(apiURL, "", false)
	err := api.register()

	details, timeStamps := getTestEvent()
	err = api.ReportEvent(details, timeStamps)
	assert.Equal(t, nil, err)
}

func TestPasswordLock(t *testing.T) {
	tempPassword := randString(20)
	confPassword := NewConfigPassword(tempPasswordFile)
	anotherConfPassword := NewConfigPassword(tempPasswordFile)

	err := confPassword.WritePassword(tempPassword)
	assert.NotEqual(t, nil, err)

	locked, err := confPassword.GetExLock()
	defer confPassword.Unlock()
	require.True(t, locked, "File lock must succeed")
	require.Equal(t, nil, err, "must be able to get lock "+tempPasswordFile)

	err = confPassword.WritePassword(tempPassword)
	require.Equal(t, nil, err, "must be able to write to"+tempPasswordFile)

	locked, err = anotherConfPassword.GetExLock()
	assert.NotEqual(t, nil, err)
	assert.False(t, locked)

	err = anotherConfPassword.WritePassword(randString(20))
	assert.NotEqual(t, nil, err)
	confPassword.Unlock()

	currentPassword, err := confPassword.ReadPassword()
	assert.Equal(t, nil, err)
	assert.Equal(t, tempPassword, currentPassword)

	tempPassword = randString(20)
	locked, err = anotherConfPassword.GetExLock()
	defer anotherConfPassword.Unlock()
	assert.Equal(t, nil, err)
	assert.True(t, locked)

	err = anotherConfPassword.WritePassword(tempPassword)
	assert.Equal(t, nil, err)

	currentPassword, err = anotherConfPassword.ReadPassword()
	assert.Equal(t, nil, err)
	assert.Equal(t, tempPassword, currentPassword)

	err = os.Remove(tempPasswordFile)
}

func createTestConfig() error {
	conf := &Config{
		ServerURL:  apiURL,
		Group:      defaultGroup,
		DeviceName: randString(10),
	}
	d, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(testConfig, d, 0600)
	return err
}

// runMultipleRegistrations registers supplied count APIs on multiple threads
// and returns a  channel in which the registered passwords will be supplied
func runMultipleRegistrations(count int) (int, chan string) {
	messages := make(chan string)

	for i := 0; i < count; i++ {
		go func() {
			api, err := NewAPIFromConfig(testConfig)
			if err != nil {
				messages <- err.Error()
			} else {
				messages <- api.device.password
			}
		}()
	}
	return count, messages
}

func removeTestConfig() {
	_ = os.Remove(testConfig)
	_ = os.Remove(privConfigFilename(testConfig))
}

func TestMultipleRegistrations(t *testing.T) {
	err := createTestConfig()
	defer removeTestConfig()

	require.Equal(t, nil, err, "Must be able to make test config "+testConfig)
	count, passwords := runMultipleRegistrations(4)
	password := <-passwords
	for i := 1; i < count; i++ {
		pass := <-passwords
		assert.Equal(t, password, pass)
	}
}

// getAPI returns a CacophonyAPI for testing purposes using provided url and password with random name
// if register is set will provide a random token and password and set justRegistered
func getAPI(url, password string, register bool) *CacophonyAPI {
	client := &CacophonyDevice{
		group:    defaultGroup,
		name:     randString(10),
		password: password,
	}

	api := &CacophonyAPI{
		serverURL:  url,
		device:     client,
		httpClient: newHTTPClient(),
	}

	if register {
		api.device.password = randString(20)
		api.token = "tok-" + randString(20)
		api.justRegistered = true
	}
	return api
}
