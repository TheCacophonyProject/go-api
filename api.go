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
	"crypto/sha1"
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
	"regexp"
	"strconv"
	"strings"
	"time"

	goconfig "github.com/TheCacophonyProject/go-config"
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
	saltId   int
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

func (api *CacophonyAPI) DeviceName() string {
	return api.device.name
}

func (api *CacophonyAPI) GroupName() string {
	return api.device.group
}

// apiFromConfig creates a CacophonyAPI from the config files. The API will need
// to be registered or be authenticated before used.
func apiFromConfig() (*CacophonyAPI, error) {
	conf, err := NewConfig(goconfig.DefaultConfigDir)
	if err != nil {
		return nil, err
	}
	if err := conf.read(); err != nil {
		return nil, err
	}

	device := &CacophonyDevice{
		group:    conf.Group,
		name:     conf.DeviceName,
		id:       conf.DeviceID,
		password: conf.DevicePassword,
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

// Register will check that there is not already device config files, will then
// register with the given parameters and then save them in new config files.
func Register(devicename, password, group, apiURL string, saltId int) (*CacophonyAPI, error) {
	url, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}

	conf, err := NewConfig(goconfig.DefaultConfigDir)
	if err != nil {
		return nil, err
	}

	if err := conf.read(); err != nil {
		return nil, err
	}

	if conf.Registered() {
		return nil, errors.New("device is already registered")
	}

	regData := map[string]interface{}{
		"group":      group,
		"devicename": devicename,
		"password":   password,
	}
	if saltId != 0 {
		regData["saltId"] = saltId
	}
	payload, err := json.Marshal(regData)
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
		saltId:   respData.SaltId,
	}
	api.token = respData.Token

	conf.DeviceID = respData.ID
	conf.DeviceName = devicename
	conf.DevicePassword = password
	conf.Group = group
	conf.ServerURL = url.String()
	if err := conf.write(); err != nil {
		return nil, err
	}
	if err := updateHostnameFiles(api.getHostname()); err != nil {
		return nil, err
	}
	return api, nil
}

// authenticate a device with Cacophony API and retrieves the token
func (api *CacophonyAPI) authenticate() error {
	if api.device.password == "" {
		return notRegisteredError
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

func shaHash(r io.Reader) (string, error) {
	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	hashString := fmt.Sprintf("%x", h.Sum(nil))
	return hashString, nil
}

// UploadVideo uploads the file to Cacophony API as a multipartmessage
func (api *CacophonyAPI) UploadVideo(r io.Reader, data map[string]interface{}) (int, error) {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	// This will write to fileBytes as it reads r to get the sha hash
	var fileBytes bytes.Buffer
	tee := io.TeeReader(r, &fileBytes)
	hash, err := shaHash(tee)
	if err != nil {
		return 0, err
	}
	if data == nil {
		data = make(map[string]interface{})
	}
	if _, ok := data["type"]; !ok {
		data["type"] = "thermalRaw"
	}
	data["fileHash"] = hash

	// JSON encoded "data" parameter.
	dataBuf, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	if err := w.WriteField("data", string(dataBuf)); err != nil {
		return 0, err
	}

	// Add the file as a new MIME part.
	fw, err := w.CreateFormFile("file", "file")
	if err != nil {
		return 0, err
	}
	io.Copy(fw, &fileBytes)
	w.Close()
	req, err := http.NewRequest("POST", joinURL(api.serverURL, apiBasePath, "/recordings"), buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", api.token)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return 0, err
	}
	var fr fileUploadResponse
	d := json.NewDecoder(resp.Body)
	if err := d.Decode(&fr); err != nil {
		return 0, err
	}
	return fr.RecordingID, nil
}

type tokenResponse struct {
	Messages []string
	Token    string
	ID       int
	SaltId   int
}

type fileUploadResponse struct {
	RecordingID int
	StatusCode  int
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
	File     FileInfo
	Jwt      string
	FileSize int
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
	if err != nil {
		return nil, err
	}
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

// formatTimestamp to time.RFC3339Nano format
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
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
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", api.token)
	// client := new(http.Client)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

// This allows the device to be registered even
func (api *CacophonyAPI) ReRegisterByAuthorized(newName, newGroup, newPassword, authToken string) error {
	data := map[string]string{
		"newName":         newName,
		"newGroup":        newGroup,
		"newPassword":     newPassword,
		"authorizedToken": authToken,
	}
	jsonAll, err := json.Marshal(data)
	if err != nil {
		return err
	}
	url := joinURL(api.serverURL, apiBasePath, "devices/reregister-authorized")
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonAll))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", api.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := api.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := handleHTTPResponse(resp); err != nil {
		return err
	}
	var respData tokenResponse
	d := json.NewDecoder(resp.Body)
	if err := d.Decode(&respData); err != nil {
		return fmt.Errorf("decode: %v", err)
	}
	api.device = &CacophonyDevice{
		id:       respData.ID,
		group:    newGroup,
		name:     newName,
		password: newPassword,
	}

	api.token = respData.Token
	api.device.password = newPassword
	conf, err := NewConfig(goconfig.DefaultConfigDir)
	if err != nil {
		return err
	}
	conf.DeviceName = newName
	conf.Group = newGroup
	conf.ServerURL = api.serverURL
	conf.DevicePassword = newPassword
	conf.DeviceID = respData.ID
	if err := conf.write(); err != nil {
		return err
	}
	return updateHostnameFiles(api.getHostname())
}

// Reregister will register getting a new name and/or group
func (api *CacophonyAPI) Reregister(newName, newGroup, newPassword string) error {
	data := map[string]string{
		"newName":     newName,
		"newGroup":    newGroup,
		"newPassword": newPassword,
	}
	jsonAll, err := json.Marshal(data)
	if err != nil {
		return err
	}

	url := joinURL(api.serverURL, apiBasePath, "devices/reregister")
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonAll))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", api.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return err
	}

	var respData tokenResponse
	d := json.NewDecoder(resp.Body)
	if err := d.Decode(&respData); err != nil {
		return fmt.Errorf("decode: %v", err)
	}
	api.device = &CacophonyDevice{
		id:       respData.ID,
		group:    newGroup,
		name:     newName,
		password: newPassword,
	}

	api.token = respData.Token
	api.device.password = newPassword

	conf, err := NewConfig(goconfig.DefaultConfigDir)
	if err != nil {
		return err
	}

	conf.DeviceName = newName
	conf.Group = newGroup
	conf.ServerURL = api.serverURL
	conf.DevicePassword = newPassword
	conf.DeviceID = respData.ID

	if err := conf.write(); err != nil {
		return err
	}

	return updateHostnameFiles(api.getHostname())
}

func (api *CacophonyAPI) getHostname() string {
	return safeName(api.device.name) + "-" + safeName(api.device.group)
}

func safeName(name string) string {
	name = strings.ToLower(name)
	reg := regexp.MustCompile("[^a-z0-9]+")
	return reg.ReplaceAllString(name, "")
}

var notRegisteredError = errors.New("device is not registered")

func IsNotRegisteredError(err error) bool {
	return err == notRegisteredError
}

// Send heart beat from device with expected next heart beat time
func (api *CacophonyAPI) Heartbeat(nextHeartBeat time.Time) ([]byte, error) {
	url := joinURL(api.serverURL, apiBasePath, "devices/heartbeat")
	data := map[string]string{
		"nextHeartbeat": nextHeartBeat.Format(time.RFC3339),
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", api.token)

	if err != nil {
		return nil, err
	}

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

// Ensure names match the API
type Settings struct {
	ReferenceImagePOV            string
	ReferenceImagePOVFileSize    int
	ReferenceImageInSitu         string
	ReferenceImageInSituFileSize int
	Warp                         Warp
	MaskRegions                  []Region
	RatThresh                    interface{}
	Success                      bool
	Messages                     []string
}

type Warp struct {
	Dimensions  Dimensions
	Origin      Point
	TopLeft     Point
	TopRight    Point
	BottomLeft  Point
	BottomRight Point
}

type Dimensions struct {
	Width  int
	Height int
}

type Point struct {
	X int
	Y int
}

type Region struct {
	RegionData []Point `json:"regionData"`
}

func (api *CacophonyAPI) GetDeviceSettings() (map[string]interface{}, error) {
	url := joinURL(api.serverURL, apiBasePath, "devices/"+strconv.Itoa(api.device.id)+"/settings")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", api.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response struct {
		Settings map[string]interface{} `json:"settings"`
		Success  bool                   `json:"success"`
		Messages []string               `json:"messages"`
	}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return response.Settings, nil
}

// UpdateDeviceSettings updates the device settings on the API and returns the updated settings
func (api *CacophonyAPI) UpdateDeviceSettings(settings map[string]interface{}) (map[string]interface{}, error) {
	url := joinURL(api.serverURL, apiBasePath, "devices/"+strconv.Itoa(api.device.id)+"/settings")
	payload, err := json.Marshal(map[string]interface{}{
		"settings": settings,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", api.token)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response struct {
		Settings map[string]interface{} `json:"settings"`
		Success  bool                   `json:"success"`
		Messages []string               `json:"messages"`
	}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return response.Settings, nil
}
