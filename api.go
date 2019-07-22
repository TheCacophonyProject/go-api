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
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"
)

const (
	httpTimeout = 60 * time.Second
	timeout     = 30 * time.Second
	apiBasePath = "/api/v1"
	regURL      = "/devices"
	authURL     = "/authenticate_device"
)

type CacophonyDevice struct {
	group    string
	name     string
	password string
	id       int
}

type CacophonyAPI struct {
	device     *CacophonyDevice
	httpClient *http.Client
	serverURL  string
	token      string
}

// joinURL creates an absolute url with supplied baseURL, and all paths
func joinURL(baseURL string, paths ...string) string {

	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	url := path.Join(paths...)
	u.Path = path.Join(u.Path, url)
	return u.String()
}

func (api *CacophonyAPI) getAPIURL() string {
	return joinURL(api.serverURL, apiBasePath)
}

func (api *CacophonyAPI) getAuthURL() string {
	return joinURL(api.serverURL, authURL)
}
func (api *CacophonyAPI) getRegURL() string {
	return joinURL(api.serverURL, apiBasePath, regURL)
}

func (api *CacophonyAPI) Password() string {
	return api.device.password
}

func (api *CacophonyAPI) DeviceID() int {
	return api.device.id
}

// apiFromConfig creates a CacophonyAPI from the config files. The API will need
// to be registered or be authenticated before used.
func apiFromConfig() (*CacophonyAPI, error) {
	conf, err := GetConfig(DeviceConfigPath)
	if err != nil {
		return nil, err
	}
	lockSafeConfig := NewLockSafeConfig(RegisteredConfigPath)
	_, err = lockSafeConfig.Read()
	if err != nil {
		return nil, err
	}

	if lockSafeConfig.config == nil || !lockSafeConfig.config.IsValid() {
		locked, err := lockSafeConfig.GetExLock()
		if locked == false || err != nil {
			return nil, err
		}
		defer lockSafeConfig.Unlock()

		//read again in case was just written to while waiting for exlock
		_, err = lockSafeConfig.Read()
		if err != nil {
			return nil, err
		}
	}

	device := &CacophonyDevice{
		group: conf.Group,
		name:  conf.DeviceName,
	}
	if lockSafeConfig.config != nil {
		device.password = lockSafeConfig.config.Password
		device.id = lockSafeConfig.config.DeviceID
	}

	api := &CacophonyAPI{
		serverURL:  conf.ServerURL,
		device:     device,
		httpClient: newHTTPClient(),
	}

	return api, err
}

// New will get an API from the config files and authenticate. Will return an
// error if the device has not been registered yet.
func New() (*CacophonyAPI, error) {
	api, err := apiFromConfig()
	if err != nil {
		return nil, err
	}
	if err := api.authenticate(); err != nil {
		return nil, err
	}
	return api, nil
}

// Register will check that there is not already deice config files, will then
// register with the given parameters and then save them in new config files.
func Register(devicename string, password string, group string, apiURL string) (*CacophonyAPI, error) {
	url, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}

	conf := &Config{
		DeviceName: devicename,
		Group:      group,
		ServerURL:  url.String(),
		filePath:   DeviceConfigPath,
	}
	if exists, err := conf.exists(); exists {
		return nil, errors.New("device config file exists")
	} else if err != nil {
		return nil, err
	}

	// Lock safe config files
	lsConf := NewLockSafeConfig(RegisteredConfigPath)
	if locked, err := lsConf.GetExLock(); err != nil {
		return nil, err
	} else if !locked {
		return nil, errors.New("could not lock private config file")
	}
	defer lsConf.Unlock()

	payload, err := json.Marshal(map[string]string{
		"group":      group,
		"devicename": devicename,
		"password":   password,
	})
	if err != nil {
		return nil, err
	}

	api := &CacophonyAPI{
		serverURL:  url.String(),
		httpClient: newHTTPClient(),
	}
	postResp, err := api.httpClient.Post(
		api.getRegURL(),
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, err
	}
	defer postResp.Body.Close()

	if err := handleHTTPResponse(postResp); err != nil {
		return nil, err
	}

	var respData tokenResponse
	d := json.NewDecoder(postResp.Body)
	if err := d.Decode(&respData); err != nil {
		return nil, fmt.Errorf("decode: %v", err)
	}
	api.device = &CacophonyDevice{
		id:       respData.ID,
		group:    group,
		name:     devicename,
		password: password,
	}
	api.token = respData.Token
	if err := lsConf.Write(api.device.id, api.Password()); err != nil {
		return nil, err
	}

	if err := conf.write(); err != nil {
		return nil, err
	}
	return api, nil
}

// authenticate a device with Cacophony API and retrieves the token
func (api *CacophonyAPI) authenticate() error {

	if api.device.password == "" {
		return &notRegisteredError{}
	}

	data := map[string]interface{}{
		"password": api.device.password,
	}
	if api.device.id > 0 {
		data["deviceID"] = api.device.id
	} else {
		data["devicename"] = api.device.name
		data["groupname"] = api.device.group
	}
	payload, err := json.Marshal(data)

	if err != nil {
		return err
	}
	postResp, err := api.httpClient.Post(
		api.getAuthURL(),
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	defer postResp.Body.Close()

	if err := handleHTTPResponse(postResp); err != nil {
		return err
	}

	var resp tokenResponse
	d := json.NewDecoder(postResp.Body)
	if err := d.Decode(&resp); err != nil {
		return fmt.Errorf("decode: %v", err)
	}
	api.device.id = resp.ID
	api.token = resp.Token
	return nil
}

// newHTTPClient initializes and returns a http.Client with default settings
func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   timeout, // connection timeout
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,

			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          5,
			IdleConnTimeout:       90 * time.Second,
		},
	}
}

// UploadThermalRaw uploads the file to Cacophony API as a multipartmessage
// with data of type thermalRaw specified
func (api *CacophonyAPI) UploadThermalRaw(r io.Reader) error {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)

	// JSON encoded "data" parameter.
	dataBuf, err := json.Marshal(map[string]string{
		"type": "thermalRaw",
	})
	if err != nil {
		return err
	}
	if err := w.WriteField("data", string(dataBuf)); err != nil {
		return err
	}

	// Add the file as a new MIME part.
	fw, err := w.CreateFormFile("file", "file")
	if err != nil {
		return err
	}
	io.Copy(fw, r)
	w.Close()

	req, err := http.NewRequest("POST", joinURL(api.serverURL, apiBasePath, "/recordings"), buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", api.token)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return err
	}

	return nil
}

type tokenResponse struct {
	Messages []string
	Token    string
	ID       int
}

type fileUploadResponse struct {
	RecordingId int
	Success     bool
	Messages    []string
}

// message gets the first message of the supplised tokenResponse if present
// otherwise default of "unknown"
func (r *tokenResponse) message() string {
	if len(r.Messages) > 0 {
		return r.Messages[0]
	}
	return "unknown"
}

// getFileFromJWT downloads a file from the Cacophony API using supplied JWT
// and saves it to the supplied path
func (api *CacophonyAPI) getFileFromJWT(jwt, filePath string) error {
	// Get the data
	u, err := url.Parse(api.serverURL)
	if err != nil {
		return err
	}
	u.Path = path.Join(apiBasePath, "/signedUrl")
	params := url.Values{}
	params.Add("jwt", jwt)
	u.RawQuery = params.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if err := handleHTTPResponse(resp); err != nil {
		return err
	}

	// Writer the body to file
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(filePath)
		return err
	}

	return nil
}

type FileResponse struct {
	File FileInfo
	Jwt  string
}

type FileInfo struct {
	Details FileDetails
	Type    string
}

type FileDetails struct {
	Name         string
	OriginalName string
}

// GetFileDetails of the supplied fileID from the Cacophony API and return FileResponse info.
// This can then be parsed into DownloadFile to download the file
func (api *CacophonyAPI) GetFileDetails(fileID int) (*FileResponse, error) {
	buf := new(bytes.Buffer)

	req, err := http.NewRequest("GET", joinURL(api.serverURL, apiBasePath, "/files/"+strconv.Itoa(fileID)), buf)
	req.Header.Set("Authorization", api.token)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var fr FileResponse
	d := json.NewDecoder(resp.Body)
	if err := d.Decode(&fr); err != nil {
		return &fr, err
	}
	return &fr, nil
}

// DownloadFile specified by fileResponse and save it to filePath
func (api *CacophonyAPI) DownloadFile(fileResponse *FileResponse, filePath string) error {
	if _, err := os.Stat(filePath); err == nil {
		return err
	}

	return api.getFileFromJWT(fileResponse.Jwt, filePath)
}

// ReportEvent described by jsonDetails and timestamps to the Cacophony API
func (api *CacophonyAPI) ReportEvent(jsonDetails []byte, times []time.Time) error {
	// Deserialise the JSON event details into a map.
	var details map[string]interface{}
	err := json.Unmarshal(jsonDetails, &details)
	if err != nil {
		return err
	}

	// Convert the event times for sending and add to the map to send.
	dateTimes := make([]string, 0, len(times))
	for _, t := range times {
		dateTimes = append(dateTimes, formatTimestamp(t))
	}
	details["dateTimes"] = dateTimes

	// Serialise the map back to JSON for sending.
	jsonAll, err := json.Marshal(details)
	if err != nil {
		return err
	}

	// Prepare request.
	req, err := http.NewRequest("POST", joinURL(api.serverURL, apiBasePath, "/events"), bytes.NewReader(jsonAll))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", api.token)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return temporaryError(err)
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return err
	}

	return nil
}

// handleHTTPResponse checks StatusCode of a response for success and returns an http error
// described in error.go
func handleHTTPResponse(resp *http.Response) error {
	if !(isHTTPSuccess(resp.StatusCode)) {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return temporaryError(fmt.Errorf("request failed (%d) and body read failed: %v", resp.StatusCode, err))
		}
		return &Error{
			message:   fmt.Sprintf("HTTP request failed (%d): %s", resp.StatusCode, body),
			permanent: isHTTPClientError(resp.StatusCode),
		}
	}
	return nil
}

//formatTimestamp to time.RFC3339 format
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func isHTTPSuccess(code int) bool {
	return code >= 200 && code < 300
}

func isHTTPClientError(code int) bool {
	return code >= 400 && code < 500
}

// GetSchedule will get the audio schedule
func (api *CacophonyAPI) GetSchedule() ([]byte, error) {
	req, err := http.NewRequest("GET", joinURL(api.serverURL, apiBasePath, "schedules"), nil)
	req.Header.Set("Authorization", api.token)
	//client := new(http.Client)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

type notRegisteredError struct{}

func (e *notRegisteredError) Error() string {
	return "device is not registered"
}

func IsNotRegisteredError(err error) bool {
	_, ok := err.(*notRegisteredError)
	return ok
}
