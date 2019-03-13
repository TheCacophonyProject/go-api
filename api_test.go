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
)

var tokenSuccess bool
var responseHeader int
var message string
var rawThermalData string = "this is the raw thermal file"

const token string = "test-token"

type TestConfig struct {
	ServerURL  string
	Group      string
	DeviceName string
	Password   string
}

var config *TestConfig

func TestRegistration(t *testing.T) {
	ts := GetRegisterServer(t)
	defer ts.Close()

	config = &TestConfig{
		ServerURL:  ts.URL,
		Group:      "group",
		DeviceName: "name",
	}
	var expected string
	passwords := []string{"", "validpass"}
	//first pas test register(), while second with a password tests newToken()
	for _, password := range passwords {
		config.Password = password
		//fail
		message = "failed due to tokenSuccess"
		tokenSuccess = false
		responseHeader = http.StatusOK
		expected := "registration failed: " + message

		api, actual := NewAPI(config.ServerURL, config.Group, config.DeviceName, config.Password)
		if actual == nil {
			t.Errorf("Error NewAPI actual = nil, and Expected = %v.", expected)
		}

		//success
		expected = ""
		tokenSuccess = true
		responseHeader = http.StatusOK
		api, actual = NewAPI(config.ServerURL, config.Group, config.DeviceName, config.Password)
		if actual != nil {
			t.Errorf("Error NewAPI actual = %v, and expected = nil.", actual)
		}
		if api.Client.token != token {
			t.Errorf("Error token actual = %v, and expected = %s.", api.Client.token, token)
		}
		if api.Client.password == "" {
			t.Errorf("Error password actual = nil and expected = %s", api.Client.password)
		}

		if password == "" && api.JustRegistered() != true {
			t.Errorf("Error JustRegistered actual = %t, and Expected = %t.", api.JustRegistered(), true)
		}
	}

	api := GetAPI()
	api.Client.password = "valid"
	expected = api.Client.password

	actual := api.register()
	if actual == nil {
		t.Errorf("Error register actual = nil and expected = %s", "error already Registered")
	}

	if api.Client.password != expected {
		t.Errorf("Error password actual = %v, and Expected = %s.", api.Client.password, expected)

	}
	api.Client.password = ""
	actual = api.newToken()
	if actual == nil {
		t.Errorf("Error password actual = nil and expected = %s", "error already set")
	}
}

//GetRegisterServer replies with a new token
func GetRegisterServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var newTokenRequest = strings.HasSuffix(r.URL.Path, "authenticate_device")
		var requestJson = map[string]string{}
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&requestJson)

		var reqType string
		if newTokenRequest {
			reqType = "newToken"
		} else {
			reqType = "register"

		}

		if newTokenRequest {
			if requestJson["password"] != config.Password {
				t.Errorf("Error %s password actual = %s and expected = %s", reqType, requestJson["password"], config.Password)
			}
		} else {
			if requestJson["group"] != config.Group {
				t.Errorf("Error %s group actual = %s and expected = %s", reqType, requestJson["group"], config.Group)
			}
		}
		if requestJson["devicename"] != config.DeviceName {
			t.Errorf("Error %s devicename actual = %s and expected = %s", reqType, requestJson["devicename"], config.DeviceName)
		}

		if requestJson["password"] == "" {
			t.Errorf("Error %s password actual = %s and expected = %s", reqType, requestJson["password"], "a value")
		}

		w.WriteHeader(responseHeader)
		w.Header().Set("Content-Type", "application/json")
		token := &tokenResponse{
			Success:  tokenSuccess,
			Messages: []string{message},
			Token:    token,
		}
		json.NewEncoder(w).Encode(token)
	}))
	return ts
}

//GetUploadThermalRawServer replies with a new token
func GetUploadThermalRawServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authToken := r.Header.Get("Authorization")

		if authToken != token {
			t.Errorf("Error uploadthermalraw token actual = %s and expected = %s", authToken, token)
		}

		partReader, err := r.MultipartReader()

		if err != nil {
			t.Errorf("Error parsing form %v", err)
			return
		}

		form, err := partReader.ReadForm(1000)
		if err != nil {
			t.Errorf("Error reading form %v", err)
			return
		}

		if val, ok := form.File["file"]; ok {
			filePart := val[0]
			file, _ := filePart.Open()
			fileData := ""
			b := make([]byte, 1)
			for {
				n, err := file.Read(b)
				fileData += string(b[:n])
				if err == io.EOF {
					break
				}
			}
			if fileData != rawThermalData {
				t.Errorf("Error mime file actual = %v, and Expected = %v.", fileData, rawThermalData)
			}
		} else {
			t.Errorf("Error mime map actual = %v, and Expected = %v.", form.File, "a key \"file\"")
		}

		if val, ok := form.Value["data"]; ok {

			dataType := val[0]
			if dataType != "{\"type\":\"thermalRaw\"}" {
				t.Errorf("Error actual = %v, and Expected = %v.", dataType, "{\"type\":\"thermalRaw\"}")
			}
		} else {
			t.Errorf("Error mime map actual = %v, and Expected = %v.", form.Value, "a key \"data\"")
		}

		w.WriteHeader(responseHeader)
	}))
	return ts
}

func GetAPI() *CacophonyAPI {

	client := &CacophonyClient{
		group:    config.Group,
		name:     config.DeviceName,
		typeName: config.DeviceName,
		password: "valid",
	}

	return &CacophonyAPI{
		serverURL:  config.ServerURL,
		Client:     client,
		httpClient: newHTTPClient(),
		regURL:     config.ServerURL + basePath + "/devices",
		authURL:    config.ServerURL + "/authenticate_device",
	}
}

func TestUploadThermalRaw(t *testing.T) {
	ts := GetUploadThermalRawServer(t)
	defer ts.Close()

	config = &TestConfig{
		ServerURL:  ts.URL,
		Group:      "group",
		DeviceName: "name",
	}
	api := GetAPI()
	api.Client.token = token

	message = "failed due to tokenSuccess"
	responseHeader = http.StatusOK

	reader := strings.NewReader(rawThermalData)
	actual := api.UploadThermalRaw(reader)
	if actual != nil {
		t.Errorf("Error actual = %v, and Expected = nil.", actual)
	}
}
