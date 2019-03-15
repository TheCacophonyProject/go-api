// go-api - Client for the Cacophony API server.
// tests against cacophony-api require apiURL to be pointing
// to a valid cacophony-api server and test-seed.sql to be run
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
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var tokenSuccess = true
var responseHeader = http.StatusOK
var message string
var rawThermalData = "this is the raw thermal file"
var apiURL = "http://localhost:1080"
var defaultDevice = "test-device"
var defaultPassword = "test-password"
var defaultGroup = "test-group"
var testEventDetail = `{"description": {"type": "test-id", "details": {"tail":"fuzzy"} } }`
var tempPasswordFile = "password.tmp"

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
		Success:  tokenSuccess,
		Messages: []string{message},
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

func createTempPasswordFile(filename, password string) error {
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0775)
	f.Truncate(0)
	f.Seek(0, 0)

	defer f.Close()
	if err != nil {
		return err
	}
	_, err = f.WriteString(password)
	return err
}

func readPassword(filename string) (string, error) {
	content, err := ioutil.ReadFile(filename)
	return string(content), err
}

func getLock(filename string) (*flock.Flock, bool, error) {
	fileLock := flock.New(tempPasswordFile)
	lockCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	locked, err := fileLock.TryLockContext(lockCtx, 678*time.Millisecond)
	return fileLock, locked, err
}

func TestPasswordLock(t *testing.T) {
	tempPassword := randString(20)
	err := createTempPasswordFile(tempPasswordFile, tempPassword)
	require.Equal(t, err, nil, "must be able to create/open "+tempPasswordFile)

	fileLock, locked, err := getLock(tempPasswordFile)
	require.True(t, locked, "File lock must succeed")
	require.Equal(t, err, nil, "File lock must succeed")

	err = WritePassword(tempPasswordFile, randString(20))
	assert.NotEqual(t, nil, err)
	fileLock.Unlock()

	currentPassword, err := readPassword(tempPasswordFile)
	assert.Equal(t, err, nil)
	assert.Equal(t, tempPassword, currentPassword)

	tempPassword = randString(20)
	err = WritePassword(tempPasswordFile, tempPassword)
	assert.Equal(t, err, nil)

	currentPassword, err = readPassword(tempPasswordFile)
	assert.Equal(t, err, nil)
	assert.NotEqual(t, currentPassword, tempPassword)

	err = os.Remove(tempPasswordFile)
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
