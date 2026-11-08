package tools

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

const browserWorkerPath = "/usr/local/bin/argos-browser-worker"
const browserStateSizeLimit = 480 << 10

var browserXSSParameter = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var browserAuthProfileID = regexp.MustCompile(`^auth_[A-Fa-f0-9]{32}$`)

type browserCredentials struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	UserSelector     string `json:"userSelector,omitempty"`
	PasswordSelector string `json:"passwordSelector,omitempty"`
	SubmitSelector   string `json:"submitSelector,omitempty"`
	SuccessSelector  string `json:"successSelector,omitempty"`
}

type browserAuthzCompare struct {
	RoleAAuthProfileID string `json:"roleAAuthProfileID"`
	RoleBAuthProfileID string `json:"roleBAuthProfileID"`
	EndpointURL        string `json:"endpointUrl"`
	RoleAStorageState  string `json:"-"`
	RoleBStorageState  string `json:"-"`
}

type browserRequest struct {
	Action         string               `json:"action"`
	URL            string               `json:"url"`
	AuthProfileID  string               `json:"authProfileID,omitempty"`
	AuthzCompare   *browserAuthzCompare `json:"authzCompare,omitempty"`
	XSSParam       string               `json:"xssParam,omitempty"`
	TimeoutSeconds int                  `json:"timeoutSeconds,omitempty"`
}

type browserAuthProfile struct {
	ID               string          `json:"id"`
	Version          int             `json:"version"`
	SessionID        string          `json:"sessionID"`
	Name             string          `json:"name"`
	Username         string          `json:"username"`
	Password         string          `json:"password"`
	UserSelector     string          `json:"userSelector,omitempty"`
	PasswordSelector string          `json:"passwordSelector,omitempty"`
	SubmitSelector   string          `json:"submitSelector,omitempty"`
	SuccessSelector  string          `json:"successSelector,omitempty"`
	StorageState     json.RawMessage `json:"storageState,omitempty"`
}

type browserWorkerAuthzCompare struct {
	RoleAStorageState string `json:"roleAStorageState"`
	RoleBStorageState string `json:"roleBStorageState"`
	EndpointURL       string `json:"endpointUrl"`
}

type browserWorkerRequest struct {
	Action         string                     `json:"action"`
	URL            string                     `json:"url"`
	Credentials    *browserCredentials        `json:"credentials,omitempty"`
	StorageState   string                     `json:"storageState,omitempty"`
	AuthzCompare   *browserWorkerAuthzCompare `json:"authzCompare,omitempty"`
	XSSParam       string                     `json:"xssParam,omitempty"`
	TimeoutSeconds int                        `json:"timeoutSeconds,omitempty"`
}

func RegisterBrowser(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.browse",
			Description: "Run a Playwright browser action inside the pinned Docker worker. All HTTP(S) traffic uses the controller scope gateway; there is no host-browser fallback.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"action": {
						Type:        "string",
						Description: "Browser action to execute.",
						Enum:        []string{"navigate", "login", "check_authz", "dom_xss"},
					},
					"url":           {Type: "string", Description: "In-scope HTTP or HTTPS URL to open or test."},
					"authProfileID": {Type: "string", Description: "Opaque Argos desktop authentication profile ID; its credentials and browser state stay in the protected local vault."},
					"authzCompare": {
						Type:     "object",
						Required: []string{"roleAAuthProfileID", "roleBAuthProfileID", "endpointUrl"},
						Properties: map[string]mcp.Property{
							"roleAAuthProfileID": {Type: "string"},
							"roleBAuthProfileID": {Type: "string"},
							"endpointUrl":        {Type: "string"},
						},
					},
					"xssParam":       {Type: "string", Description: "Query parameter name to probe for DOM XSS (default q)."},
					"timeoutSeconds": {Type: "integer", Description: "Per-page timeout in seconds (default 30; maximum 120).", Default: 30},
				},
				Required: []string{"action", "url"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(call mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			return executeBrowserTool(call, params, env)
		},
	)
}

func executeBrowserTool(call mcp.ToolContext, params json.RawMessage, env *Env) (interface{}, *mcp.ErrorObj) {
	if len(params) > 1<<20 {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "browser request exceeds the 1 MiB input limit"}
	}
	if _, ok := scopeConfigFromToolContext(call); !ok {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: controller session, operation, and scope snapshot are required; browser action blocked"}
	}
	var input browserRequest
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, invalidParams(err)
	}
	if input.Action != "navigate" && input.Action != "login" && input.Action != "check_authz" && input.Action != "dom_xss" {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "action must be navigate, login, check_authz, or dom_xss"}
	}
	if len(input.URL) > 4096 {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "browser URL exceeds the 4096 character limit"}
	}
	target, errObj := validateWebTargetWithToolContext(env, call, input.URL)
	if errObj != nil {
		return nil, errObj
	}
	input.URL = target
	if input.TimeoutSeconds == 0 {
		input.TimeoutSeconds = 30
	}
	if input.TimeoutSeconds < 1 || input.TimeoutSeconds > 120 {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "timeoutSeconds must be between 1 and 120"}
	}
	ctx := toolContext(call)
	var authProfile *browserAuthProfile
	var workerInputState string
	switch input.Action {
	case "login":
		if input.AuthProfileID == "" {
			return nil, &mcp.ErrorObj{Code: -32602, Message: "authProfileID is required for login"}
		}
		profile, profileError := loadBrowserAuthProfile(ctx, env, call.SessionID, input.AuthProfileID)
		if profileError != nil {
			return nil, profileError
		}
		authProfile = profile
	case "navigate":
		if input.AuthProfileID != "" {
			profile, profileError := loadBrowserAuthProfile(ctx, env, call.SessionID, input.AuthProfileID)
			if profileError != nil {
				return nil, profileError
			}
			if !validBrowserStorageState(string(profile.StorageState)) {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "authentication profile has no saved browser session"}
			}
			authProfile = profile
			workerInputState = string(profile.StorageState)
		}
	case "check_authz":
		if input.AuthzCompare == nil {
			return nil, &mcp.ErrorObj{Code: -32602, Message: "authzCompare is required for check_authz"}
		}
		endpoint, endpointError := validateWebTargetWithToolContext(env, call, input.AuthzCompare.EndpointURL)
		if endpointError != nil {
			return nil, endpointError
		}
		input.AuthzCompare.EndpointURL = endpoint
		roleAProfile, profileError := loadBrowserAuthProfile(ctx, env, call.SessionID, input.AuthzCompare.RoleAAuthProfileID)
		if profileError != nil {
			return nil, profileError
		}
		roleBProfile, profileError := loadBrowserAuthProfile(ctx, env, call.SessionID, input.AuthzCompare.RoleBAuthProfileID)
		if profileError != nil {
			return nil, profileError
		}
		if !validBrowserStorageState(string(roleAProfile.StorageState)) || !validBrowserStorageState(string(roleBProfile.StorageState)) {
			return nil, &mcp.ErrorObj{Code: -32602, Message: "authorization profiles must have saved browser sessions"}
		}
		input.AuthzCompare.RoleAStorageState = string(roleAProfile.StorageState)
		input.AuthzCompare.RoleBStorageState = string(roleBProfile.StorageState)
	case "dom_xss":
		if input.XSSParam == "" {
			input.XSSParam = "q"
		}
		if !browserXSSParameter.MatchString(input.XSSParam) {
			return nil, &mcp.ErrorObj{Code: -32602, Message: "xssParam must contain only letters, digits, dots, underscores, or hyphens"}
		}
	}
	workerRequest := browserWorkerRequest{
		Action:         input.Action,
		URL:            input.URL,
		StorageState:   workerInputState,
		XSSParam:       input.XSSParam,
		TimeoutSeconds: input.TimeoutSeconds,
	}
	if input.Action == "login" && authProfile != nil {
		workerRequest.Credentials = &browserCredentials{
			Username:         authProfile.Username,
			Password:         authProfile.Password,
			UserSelector:     authProfile.UserSelector,
			PasswordSelector: authProfile.PasswordSelector,
			SubmitSelector:   authProfile.SubmitSelector,
			SuccessSelector:  authProfile.SuccessSelector,
		}
	}
	if input.AuthzCompare != nil {
		workerRequest.AuthzCompare = &browserWorkerAuthzCompare{
			RoleAStorageState: input.AuthzCompare.RoleAStorageState,
			RoleBStorageState: input.AuthzCompare.RoleBStorageState,
			EndpointURL:       input.AuthzCompare.EndpointURL,
		}
	}
	workerInput, err := json.Marshal(workerRequest)
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: "could not encode browser worker request"}
	}
	workDir, err := os.MkdirTemp("", "argos-browser-worker-")
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: "could not create a private empty browser worker directory"}
	}
	defer os.RemoveAll(workDir)
	workerRun := run(toolContext(call), browserWorkerPath, runOptions{
		Stdin:   string(workerInput),
		Timeout: time.Duration(input.TimeoutSeconds+30) * time.Second,
		MaxOut:  4 << 20,
		Dir:     workDir,
	})
	if workerRun.TimedOut {
		return nil, &mcp.ErrorObj{Code: -32000, Message: "browser worker timed out; no host-browser fallback was attempted"}
	}
	if workerRun.ExitCode != 0 {
		if authProfile != nil || input.Action == "check_authz" {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "authenticated browser worker failed"}
		}
		message := strings.TrimSpace(workerRun.Stderr)
		if message == "" {
			message = "browser worker failed"
		}
		if len(message) > 1000 {
			message = message[len(message)-1000:]
		}
		return nil, &mcp.ErrorObj{Code: -32603, Message: "browser worker failed: " + message}
	}
	if workerRun.OutputTruncated {
		return nil, &mcp.ErrorObj{Code: -32603, Message: "browser worker output exceeded the 4 MiB response limit"}
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(workerRun.Output), &result); err != nil || result == nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: "browser worker returned an invalid JSON response"}
	}
	if rawState, exists := result["storageState"]; exists {
		delete(result, "storageState")
		if input.Action != "login" || authProfile == nil {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "browser worker returned unexpected authentication state"}
		}
		state, ok := rawState.(string)
		if !ok || !validBrowserStorageState(state) {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "browser worker returned invalid authentication state"}
		}
		if result["authenticationStatus"] == "not_authenticated" {
			result["success"] = false
			sanitizeBrowserOutput(result, input.Action)
			return result, nil
		}
		authProfile.StorageState = json.RawMessage(state)
		encodedProfile, err := json.Marshal(authProfile)
		if err != nil || env.AuthVault == nil || env.AuthVault.Put(ctx, input.AuthProfileID, string(encodedProfile)) != nil {
			return nil, &mcp.ErrorObj{Code: -32000, Message: "secure authentication profile could not be saved"}
		}
		delete(result, "title")
		result["authProfileID"] = input.AuthProfileID
	}
	sanitizeBrowserOutput(result, input.Action)
	return result, nil
}

func sanitizeBrowserOutput(result map[string]interface{}, action string) {
	allowed := map[string]map[string]struct{}{
		"navigate": {
			"action": {}, "url": {}, "success": {}, "title": {}, "links": {}, "forms": {},
		},
		"login": {
			"action": {}, "url": {}, "success": {}, "authenticationStatus": {}, "authProfileID": {},
		},
		"check_authz": {
			"action": {}, "url": {}, "success": {}, "authzDiscrepancy": {},
		},
		"dom_xss": {
			"action": {}, "url": {}, "success": {}, "title": {}, "domXssSinks": {},
		},
	}
	fields := allowed[action]
	for key := range result {
		if _, ok := fields[key]; !ok {
			delete(result, key)
		}
	}
}

func loadBrowserAuthProfile(ctx context.Context, env *Env, sessionID, profileID string) (*browserAuthProfile, *mcp.ErrorObj) {
	if strings.TrimSpace(sessionID) == "" || !browserAuthProfileID.MatchString(profileID) || env == nil || env.AuthVault == nil {
		return nil, &mcp.ErrorObj{Code: -32000, Message: "secure authentication profile is unavailable"}
	}
	encoded, err := env.AuthVault.Get(ctx, profileID)
	if err != nil || encoded == nil {
		return nil, &mcp.ErrorObj{Code: -32000, Message: "secure authentication profile is unavailable"}
	}
	var profile browserAuthProfile
	if json.Unmarshal([]byte(*encoded), &profile) != nil || profile.ID != profileID || profile.Version != 1 || profile.SessionID != sessionID ||
		profile.Name == "" || len(profile.Name) > 120 ||
		profile.Username == "" || profile.Password == "" || len(profile.Username) > 4096 || len(profile.Password) > 4096 ||
		len(profile.UserSelector) > 512 || len(profile.PasswordSelector) > 512 || len(profile.SubmitSelector) > 512 || len(profile.SuccessSelector) > 512 {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "authentication profile is invalid or belongs to another Argos session"}
	}
	if len(profile.StorageState) > 0 && !validBrowserStorageState(string(profile.StorageState)) {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "authentication profile browser state is invalid"}
	}
	return &profile, nil
}

func validBrowserStorageState(raw string) bool {
	if strings.TrimSpace(raw) == "" || len(raw) > browserStateSizeLimit {
		return false
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &state); err != nil || state == nil {
		return false
	}
	return true
}
