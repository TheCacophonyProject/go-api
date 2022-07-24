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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	goconfig "github.com/TheCacophonyProject/go-config"
	"github.com/TheCacophonyProject/go-config/configtest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tests against cacophony-api require apiURL to be pointing
// to a valid cacophony-api server and test-seed.sql to be run

const (
	apiURL              = "http://localhost:1080"
	defaultDevice       = "test-device"
	defaultPassword     = "test-password"
	defaultGroup        = "test-group"
	defaultGroup2       = "test-group-2"
	defaultUsername     = "go-api-user-test"
	defaultuserPassword = "test-user-password"
	filesURL            = "/files"
	hostsFileString     = `127.0.0.1 raspberrypi
::1 localhost
`
)

const rawFileSize = 100

var responseHeader = http.StatusOK
var rawThermalData = randString(100)
var rawFileData = randString(rawFileSize)
var testCPTVFile = "test-files/test.cptv"
var testEventDetail = `{"description": {"type": "test-id", "details": {"tail":"fuzzy"} } }`

func TestMain(m *testing.M) {
	api := getAPI(apiURL, defaultPassword, false)
	api.device.name = defaultDevice
	err := api.authenticate()
	if err != nil {
		log.Println(err)
		log.Printf(`
	failed to authenticate to API.
	Check that you have a cacophony-api running on '%s' and have run 'test-seed.sql'
	Check README.md for more details.`, apiURL)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestNewTokenHttpRequest(t *testing.T) {
	ts := GetNewAuthenticateServer(t)
	defer ts.Close()

	api := getAPI(ts.URL, "", true)
	err := api.authenticate()
	assert.NoError(t, err)
}

func TestUploadVideoHttpRequest(t *testing.T) {
	ts := GetUploadVideoServer(t)
	defer ts.Close()

	api := getAPI(ts.URL, "", true)
	reader := strings.NewReader(rawThermalData)
	id, err := api.UploadVideo(reader, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
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
func getMimeParts(r *http.Request) (map[string]interface{}, string) {
	partReader, _ := r.MultipartReader()

	var fileData string
	var data map[string]interface{}
	form, err := partReader.ReadForm(1000)
	if err != nil {
		return data, ""
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
		json.Unmarshal([]byte(val[0]), &data)
	}
	return data, fileData
}

//GetUploadVideoServer checks that the message is multipart and contains the required multipartmime file:file and Value:data
//and Authorization header
func GetUploadVideoServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.NotEmpty(t, r.Header.Get("Authorization"))

		dataType, file := getMimeParts(r)
		assert.Equal(t, "thermalRaw", dataType["type"])
		_, hashExists := dataType["fileHash"]
		assert.True(t, hashExists)

		assert.Equal(t, rawThermalData, file)
		w.WriteHeader(responseHeader)

		var fr fileUploadResponse
		fr.RecordingID = 1
		fr.StatusCode = 200
		fr.Messages = []string{"All G"}
		json.NewEncoder(w).Encode(fr)
	}))
	return ts
}

func TestAPIAuthenticate(t *testing.T) {
	api := getAPI(apiURL, defaultPassword, false)
	api.device.name = defaultDevice
	err := api.authenticate()
	assert.NoError(t, err)
	assert.NotEmpty(t, api.token)
}

func randomRegister() (*CacophonyAPI, error) {
	return Register(randString(20), randString(20), defaultGroup, apiURL, int(rand.Int31()))
}

func TestAPIUploadVideo(t *testing.T) {
	defer newFs(t, "")()
	api, err := randomRegister()
	require.NoError(t, err)

	reader, err := os.Open(testCPTVFile)
	assert.NoError(t, err)
	defer reader.Close()

	id, err := api.UploadVideo(reader, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
}

func getTestEvent() ([]byte, []time.Time) {
	details := []byte(testEventDetail)
	timeStamps := []time.Time{time.Now()}
	return details, timeStamps
}

func TestAPIReportEvent(t *testing.T) {
	defer newFs(t, "")()
	api, err := randomRegister()
	require.NoError(t, err)
	details, timeStamps := getTestEvent()
	err = api.ReportEvent(details, timeStamps)
	assert.NoError(t, err)
}

// runMultipleRegistrations registers supplied count APIs with configFile on multiple threads
// and returns a channel in which the registered passwords will be supplied
func runMultipleRegistrations(count int) (int, chan string) {
	messages := make(chan string)

	for i := 0; i < count; i++ {
		go func() {
			api, err := New()
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
	count, passwords := runMultipleRegistrations(4)
	password := <-passwords
	for i := 1; i < count; i++ {
		pass := <-passwords
		assert.Equal(t, password, pass)
	}
}

func TestRegisterAndNew(t *testing.T) {
	defer newFs(t, "")()

	_, err := New()
	assert.Error(t, err, "error must be thrown if not yet registered")
	assert.True(t, IsNotRegisteredError(err), err.Error())

	name := randString(10)
	password := randString(10)
	api1, err := Register(name, password, defaultGroup, apiURL, 100)
	require.NoError(t, err, "failed to register")
	assert.Equal(t, api1.device.name, name, "name does not match what was registered with")
	assert.Equal(t, api1.device.group, defaultGroup, "group does not match what was registered with")
	assert.Equal(t, api1.Password(), password, "password does not match what was registered with")
	assert.Equal(t, api1.getHostname(), getHostnameFromFile(t))
	assert.Equal(t, 100, api1.device.saltId)
	assert.NoError(t, checkHostsFile(api1))

	api2, err := New()
	require.NoError(t, err, "failed to login after register")
	assert.Equal(t, api1.DeviceID(), api2.DeviceID(), "deviceID does not match what was registered with")
	assert.Equal(t, api2.device.name, name, "name does not match what was registered with")
	assert.Equal(t, api2.device.group, defaultGroup, "group does not match what was registered with")
	assert.Equal(t, api2.Password(), password, "password does not match what was registered with")
	assert.NoError(t, checkHostsFile(api2))

	reader, err := os.Open(testCPTVFile)
	assert.NoError(t, err)
	defer reader.Close()

	id, err := api2.UploadVideo(reader, nil)
	assert.NoError(t, err, "check that api can upload recordings")
	assert.NotEmpty(t, id, "check that recording id is not 0")

	assert.NoError(t, checkHostsFile(api2))

	_, err = Register(name+"a", defaultPassword, defaultGroup, apiURL, 0)
	assert.Error(t, err, "must not be able to register when the device is already registered")
}

func TestIsNotRegisteredError(t *testing.T) {
	assert.True(t, IsNotRegisteredError(notRegisteredError))
	assert.False(t, IsNotRegisteredError(errors.New("a error")))
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
		api.device.id = 1
	}
	return api
}

func TestFileDownload(t *testing.T) {
	defer newFs(t, "")()
	api, err := randomRegister()
	require.NoError(t, err)

	token := getUserToken(t)

	fileID := uploadFile(token, t)

	filePath := path.Join(os.TempDir(), randString(10))
	defer os.Remove(filePath)

	fileResponse, err := api.GetFileDetails(fileID)
	require.NoError(t, err)
	err = api.DownloadFile(fileResponse, filePath)
	require.NoError(t, err)
	assert.Equal(t, fileResponse.FileSize, rawFileSize)

	fileData, err := ioutil.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, rawFileData, string(fileData))
}

func TestDeviceReregister(t *testing.T) {
	defer newFs(t, "")()
	api, err := randomRegister()
	require.NoError(t, err)
	assert.Equal(t, api.getHostname(), getHostnameFromFile(t))
	assert.NoError(t, checkHostsFile(api))

	originalName := api.device.name
	originalGroup := api.device.group
	origionalToken := api.token
	origionalPassword := api.Password()
	origionalServerURL := api.serverURL
	newName := randString(10)
	notAGroupName := randString(10)
	newPassword := randString(10)

	// fail to reregister
	require.Error(t, api.Reregister(newName, notAGroupName, newPassword),
		"shouldn't be able to change to a group that doesn't exist")
	assert.Equal(t, api.device.name, originalName,
		"name shouldn't have changed if rename failed")
	assert.Equal(t, api.device.group, originalGroup,
		"group shouldn't have changed if rename failed")
	assert.Equal(t, api.token, origionalToken,
		"JWT shouldn't have changed if rename failed")
	assert.Equal(t, api.Password(), origionalPassword,
		"password shouldn't have changed if rename failed")
	assert.Equal(t, api.serverURL, origionalServerURL,
		"serverURL shouldn't have changed if rename failed")
	assert.Equal(t, api.getHostname(), getHostnameFromFile(t))
	assert.NoError(t, checkHostsFile(api))

	// reregister
	require.NoError(t, api.Reregister(newName, defaultGroup2, newPassword))
	assert.Equal(t, api.device.name, newName,
		"name should have changed to the new name")
	assert.Equal(t, api.device.group, defaultGroup2,
		"group should have changed to the new group")
	assert.NotEqual(t, api.token, origionalToken,
		"JWT should have changed")
	assert.Equal(t, api.Password(), newPassword,
		"password should have changed to the new password")
	assert.Equal(t, api.serverURL, origionalServerURL,
		"serverURL shouldn't have changed if rename failed")
	assert.Equal(t, api.getHostname(), getHostnameFromFile(t))
	assert.NoError(t, checkHostsFile(api))

	// login again and check device and group name
	api2, err := New()
	require.NoError(t, err)
	assert.Equal(t, api2.device.name, newName,
		"name should have changed to the new name")
	assert.Equal(t, api2.device.group, defaultGroup2,
		"group should have changed to the new group")
	assert.Equal(t, api2.getHostname(), getHostnameFromFile(t))
	assert.NoError(t, checkHostsFile(api2))

	reader, err := os.Open(testCPTVFile)
	assert.NoError(t, err)
	defer reader.Close()

	id, err := api2.UploadVideo(reader, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestLoadConfig(t *testing.T) {
	defer newFs(t, "")()
	api, err := randomRegister()
	require.NoError(t, err)
	config, err := NewConfig(goconfig.DefaultConfigDir)
	require.NoError(t, err)
	require.NoError(t, config.read())
	require.Equal(t, api.DeviceName(), config.DeviceName)
	require.Equal(t, api.GroupName(), config.Group)
	require.Equal(t, api.serverURL, config.ServerURL)
}

func TestBadConfig(t *testing.T) {
	defer newFs(t, "./test-files/bad-config.toml")()
	conf, err := NewConfig(goconfig.DefaultConfigDir)
	require.NoError(t, err)
	require.Error(t, conf.read())
}

func TestStringProcessing(t *testing.T) {
	assert.Equal(t, "testname", safeName("TeSt!@#$%^&*()`~_name"))
	assert.Equal(t, "testname", safeName("-!TeSt!@#$%^&*()`~_name-_"))
}

func uploadFile(userToken string, t *testing.T) int {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	dataBuf, err := json.Marshal(map[string]string{
		"type": "audiobait",
	})
	require.NoError(t, err)
	assert.NoError(t, w.WriteField("data", string(dataBuf)))

	fw, err := w.CreateFormFile("file", "file")
	assert.NoError(t, err)

	r := strings.NewReader(rawFileData)
	_, err = io.Copy(fw, r)
	require.NoError(t, err)
	w.Close()

	url := joinURL(apiURL, apiBasePath, filesURL)
	req, err := http.NewRequest("POST", url, buf)
	require.NoError(t, err)

	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", userToken)

	resp, err := newHTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)
	var respData fileUploadResponse
	require.NoError(t, d.Decode(&respData))
	return respData.RecordingID
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

func getHostnameFromFile(t *testing.T) string {
	b, err := afero.ReadFile(Fs, hostnameFile)
	require.NoError(t, err)
	return string(b)
}

func checkHostsFile(api *CacophonyAPI) error {
	input, err := afero.ReadFile(Fs, hostsFile)
	if err != nil {
		return err
	}
	hostsString := string(input)
	substr := fmt.Sprintf(hostsFileFormat, api.getHostname()) + "\n"
	if strings.Contains(hostsString, substr) {
		return nil
	}
	return fmt.Errorf("hosts file not formatted correctly. Could not find '%s'", substr)
}

func newFs(t *testing.T, configFile string) func() {
	Fs = afero.NewMemMapFs()
	goconfig.SetFs(Fs)
	require.NoError(t, afero.WriteFile(Fs, hostsFile, []byte(hostsFileString), 0644))
	fsConfigFile := path.Join(goconfig.DefaultConfigDir, goconfig.ConfigFileName)
	lockFileFunc, cleanupFunc := configtest.WriteConfigFromFile(t, configFile, fsConfigFile, Fs)
	goconfig.SetLockFilePath(lockFileFunc)
	return cleanupFunc
}
