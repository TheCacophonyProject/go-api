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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var tokenSuccess bool = true
var responseHeader int = http.StatusOK
var message string
var rawThermalData string = "this is the raw thermal file"
var apiURL string = "http://localhost:1080"

func TestRegistrationHttpRequest(t *testing.T) {
	ts := GetRegisterServer(t)
	defer ts.Close()
	api := getAPI(ts.URL, "", false)
	err := api.register()
	assert.Equal(t, nil, err)
}

func TestNewTokenHttpRequest(t *testing.T) {
	ts := GetNewTokenServer(t)
	defer ts.Close()

	api := getAPI(ts.URL, "", true)
	err := api.authenticate()
	assert.Equal(t, err, nil)
}

func TestUploadThermalRawHttpRequest(t *testing.T) {
	ts := GetUploadThermalRawServer(t)
	defer ts.Close()

	api := getAPI(apiURL, "", false)
	api.register()
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

//GetRegisterServer replies with a new token
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

//GetRegisterServer replies with a new token
func GetNewTokenServer(t *testing.T) *httptest.Server {
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

//GetUploadThermalRawServer checks that the message is multipart and contains file:file and Value:data
func GetUploadThermalRawServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasSuffix(r.URL.Path, "/recordings"))
		assert.Equal(t, http.MethodPost, r.Method)
		assert.NotEqual(t, nil, r.Header.Get("Authorization"))

		dataType, file := getMimeParts(r)
		assert.Equal(t, "{\"type\":\"thermalRaw\"}", dataType)
		assert.Equal(t, rawThermalData, file)

		w.WriteHeader(responseHeader)
	}))
	return ts
}

func TestAPIRegistration(t *testing.T) {
	api := getAPI(apiURL, "", false)
	err := api.authenticate()
	assert.NotEqual(t, nil, err)

	err = api.register()
	assert.True(t, api.JustRegistered())
	assert.Equal(t, nil, err)
	assert.NotEqual(t, "", api.device.password)
	assert.NotEqual(t, "", api.token)
	assert.True(t, api.JustRegistered())

	err = api.authenticate()
	assert.Equal(t, err, nil)
}

func TestAPIUploadThermalRaw(t *testing.T) {
	api := getAPI(apiURL, "", false)
	err := api.register()

	reader := strings.NewReader(rawThermalData)
	err = api.UploadThermalRaw(reader)
	assert.Equal(t, nil, err)
}

func getTestEvent() ([]byte, []time.Time) {
	details := []byte(`{"description": {"type": "test-id", "details": {"tail":"fuzzy"} } }`)
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

func getAPI(url, password string, register bool) *CacophonyAPI {
	client := &CacophonyDevice{
		group:    "test-group",
		name:     randString(10),
		password: password,
	}

	api := &CacophonyAPI{
		serverURL:  url,
		device:     client,
		httpClient: newHTTPClient(),
		regURL:     url + basePath + "/devices",
		authURL:    url + "/authenticate_device",
	}

	if register {
		api.device.password = randString(20)
		api.token = "tok-" + randString(20)
		api.justRegistered = true
	}
	return api
}
