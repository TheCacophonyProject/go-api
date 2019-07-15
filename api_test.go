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
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

// tests against cacophony-api require apiURL to be pointing
// to a valid cacophony-api server and test-seed.sql to be run

const (
	apiURL              = "http://localhost:1080"
	defaultDevice       = "test-device"
	defaultPassword     = "test-password"
	defaultGroup        = "test-group"
	defaultUsername     = "go-api-user-test"
	defaultuserPassword = "test-user-password"
	filesURL            = "/files"
)

var responseHeader = http.StatusOK
var rawThermalData = randString(100)
var rawFileData = randString(100)
var testEventDetail = `{"description": {"type": "test-id", "details": {"tail":"fuzzy"} } }`

//Tests against httptest

func TestRegistrationHttpRequest(t *testing.T) {
	ts := GetRegisterServer(t)
	defer ts.Close()
	api := getAPI(ts.URL, "", false)
	err := api.register()
	assert.NoError(t, err)
}

func TestNewTokenHttpRequest(t *testing.T) {
	ts := GetNewAuthenticateServer(t)
	defer ts.Close()

	api := getAPI(ts.URL, "", true)
	err := api.authenticate()
	assert.NoError(t, err)
}

func TestUploadThermalRawHttpRequest(t *testing.T) {
	ts := GetUploadThermalRawServer(t)
	defer ts.Close()

	api := getAPI(ts.URL, "", true)
	reader := strings.NewReader(rawThermalData)
	err := api.UploadThermalRaw(reader)
	assert.NoError(t, err)
}

func getTokenResponse() *tokenResponse {
	return &tokenResponse{
		Messages: []string{},
		Token:    "tok-" + randString(20),
		ID:       1,
	}
}

func getJSONRequestMap(r *http.Request) map[string]interface{} {
	var requestJson map[string]interface{}
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
		assert.NotEmpty(t, requestJson["password"])
		assert.NotEmpty(t, requestJson["group"])
		assert.NotEmpty(t, requestJson["devicename"])

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
		assert.NotEmpty(t, requestJson["password"])
		assert.True(t, (requestJson["groupname"] != "" && requestJson["devicename"] != "") || requestJson["deviceID"] != "")

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
		assert.NotEmpty(t, r.Header.Get("Authorization"))

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
	assert.Error(t, err)

	err = api.register()
	assert.NoError(t, err)
	assert.True(t, api.JustRegistered())
	assert.NotEqual(t, "", api.device.password)
	assert.NotEqual(t, "", api.token)
	assert.True(t, api.JustRegistered())

	err = api.authenticate()
	assert.NoError(t, err)
}

func TestAPIAuthenticate(t *testing.T) {
	api := getAPI(apiURL, defaultPassword, false)
	api.device.name = defaultDevice
	err := api.authenticate()
	assert.NoError(t, err)
	assert.NotEmpty(t, api.token)
}

func TestAPIUploadThermalRaw(t *testing.T) {
	api := getAPI(apiURL, "", false)
	err := api.register()

	reader := strings.NewReader(rawThermalData)
	err = api.UploadThermalRaw(reader)
	assert.NoError(t, err)
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
	assert.NoError(t, err)
}

func getTempPasswordConfig(t *testing.T) (string, func(), *LockSafeConfig, *LockSafeConfig) {
	tmpFile, err := ioutil.TempFile("", "test-password")
	require.NoError(t, err, "Must be able to create test password file")
	tmpFile.Close()
	cleanUpFunc := func() {
		_ = os.Remove(tmpFile.Name())
	}

	confPassword := NewLockSafeConfig(tmpFile.Name())
	anotherConfPassword := NewLockSafeConfig(tmpFile.Name())

	return tmpFile.Name(), cleanUpFunc, confPassword, anotherConfPassword
}

func TestPasswordLock(t *testing.T) {
	filename, cleanUp, confPassword, anotherConfPassword := getTempPasswordConfig(t)
	defer cleanUp()
	tempPassword := randString(20)

	err := confPassword.Write(1, tempPassword)
	assert.Error(t, err)

	locked, err := confPassword.GetExLock()
	defer confPassword.Unlock()
	require.True(t, locked, "File lock must succeed")
	require.NoError(t, err, "must be able to get lock "+filename)

	err = confPassword.Write(2, tempPassword)
	require.NoError(t, err, "must be able to write to"+filename)

	locked, err = anotherConfPassword.GetExLock()
	assert.Error(t, err)
	assert.False(t, locked)

	err = anotherConfPassword.Write(3, randString(20))
	assert.Error(t, err)
	confPassword.Unlock()

	conf, err := confPassword.Read()
	assert.NoError(t, err)
	assert.Equal(t, tempPassword, conf.Password)

	tempPassword = randString(20)
	locked, err = anotherConfPassword.GetExLock()
	defer anotherConfPassword.Unlock()
	assert.NoError(t, err)
	assert.True(t, locked)

	err = anotherConfPassword.Write(1, tempPassword)
	assert.NoError(t, err)

	conf, err = anotherConfPassword.Read()
	assert.NoError(t, err)
	assert.Equal(t, tempPassword, conf.Password)

	err = os.Remove(filename)
}

//createTestConfig creates device.yaml
func createTestConfig(t *testing.T) string {
	conf := &Config{
		ServerURL:  apiURL,
		Group:      defaultGroup,
		DeviceName: randString(10),
	}
	d, err := yaml.Marshal(conf)
	require.NoError(t, err, "Must be able to make Config yaml")

	Fs = afero.NewMemMapFs()
	afero.WriteFile(Fs, DeviceConfigPath, d, 0600)

	return DeviceConfigPath
}

// TestConfigFile test registered config is created with deviceid and password
func TestConfigFile(t *testing.T) {
	_ = createTestConfig(t)
	_, err := ApiFromRegister()
	assert.NoError(t, err)
	lockSafeConfig := NewLockSafeConfig(RegisteredConfigPath)
	config, err := lockSafeConfig.Read()
	require.NoError(t, err, "Must be able to read "+RegisteredConfigPath)
	assert.NotEmpty(t, config.Password)

	_, err = ApiFromAuthenticate()
	assert.NoError(t, err)
}

// runMultipleRegistrations registers supplied count APIs with configFile on multiple threads
// and returns a channel in which the registered passwords will be supplied
func runMultipleRegistrations(configFile string, count int) (int, chan string) {
	messages := make(chan string)

	for i := 0; i < count; i++ {
		go func() {
			api, err := ApiFromAuthenticate()
			if err != nil {
				messages <- err.Error()
			} else {
				messages <- api.device.password
			}
		}()
	}
	return count, messages
}

func TestMultipleRegistrations(t *testing.T) {
	configFile := createTestConfig(t)
	count, passwords := runMultipleRegistrations(configFile, 4)
	password := <-passwords
	for i := 1; i < count; i++ {
		pass := <-passwords
		assert.Equal(t, password, pass)
	}
}

func TestAuthenticateAndRegister(t *testing.T) {
	_, err := ApiFromAuthenticate()
	assert.Error(t, err, "error must be thrown if not yet registered")

	_, err = ApiFromRegister()
	assert.NoError(t, err, "no error first time registering")

	_, err = ApiFromAuthenticate()
	assert.NoError(t, err, "must be able to authenticate after register")

	_, err = ApiFromRegister()
	assert.Error(t, err, "must not be able to register twice")
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
		api.device.id = 1
	}
	return api
}

func TestFileDownload(t *testing.T) {
	token := getUserToken(t)

	fileID := uploadFile(token, t)

	api := getAPI(apiURL, "", false)
	assert.NoError(t, api.register())

	filePath := path.Join(os.TempDir(), randString(10))
	defer os.Remove(filePath)
	fileResponse, err := api.GetFileDetails(fileID)
	assert.NoError(t, err)
	err = api.DownloadFile(fileResponse, filePath)
	assert.NoError(t, err)

	fileData, err := ioutil.ReadFile(filePath)
	assert.NoError(t, err)
	assert.Equal(t, rawFileData, string(fileData))
}

func uploadFile(userToken string, t *testing.T) int {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	dataBuf, err := json.Marshal(map[string]string{
		"type": "audiobait",
	})
	assert.NoError(t, err)
	assert.NoError(t, w.WriteField("data", string(dataBuf)))

	fw, err := w.CreateFormFile("file", "file")
	assert.NoError(t, err)

	r := strings.NewReader(rawFileData)
	io.Copy(fw, r)
	w.Close()

	url := joinURL(apiURL, apiBasePath, filesURL)
	req, err := http.NewRequest("POST", url, buf)
	assert.NoError(t, err)

	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", userToken)

	resp, err := newHTTPClient().Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)
	var respData fileUploadResponse
	assert.NoError(t, d.Decode(&respData))
	return respData.RecordingId
}

// getUserToken is needed for testing purposes to be able to upload files as a
// user so TestFileDownload can be properly tested.
func getUserToken(t *testing.T) string {
	data := map[string]interface{}{
		"username": defaultUsername,
		"password": defaultuserPassword,
	}
	payload, err := json.Marshal(data)
	assert.NoError(t, err)
	httpClient := newHTTPClient()
	postResp, err := httpClient.Post(
		joinURL(apiURL, "/authenticate_user"),
		"application/json",
		bytes.NewReader(payload),
	)
	assert.NoError(t, err)
	defer postResp.Body.Close()

	assert.NoError(t, handleHTTPResponse(postResp))

	var resp tokenResponse
	d := json.NewDecoder(postResp.Body)
	assert.NoError(t, d.Decode(&resp))
	return resp.Token
}
