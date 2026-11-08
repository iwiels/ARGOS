package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

const ProtocolVersion = "2025-03-26"

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *ErrorObj   `json:"error,omitempty"`
}

type ErrorObj struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

var (
	ErrMethodNotFound = &ErrorObj{Code: -32601, Message: "Method not found"}
	ErrInvalidParams  = &ErrorObj{Code: -32602, Message: "Invalid params"}
	ErrInternal       = &ErrorObj{Code: -32603, Message: "Internal error"}
)

type ToolAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

type ToolInputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type                 string              `json:"type"`
	Description          string              `json:"description,omitempty"`
	Items                *Items              `json:"items,omitempty"`
	Properties           map[string]Property `json:"properties,omitempty"`
	Required             []string            `json:"required,omitempty"`
	Enum                 []string            `json:"enum,omitempty"`
	AdditionalProperties *bool               `json:"additionalProperties,omitempty"`
	Default              interface{}         `json:"default,omitempty"`
}

type Items struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

type ToolDefinition struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema ToolInputSchema  `json:"inputSchema"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

type ToolHandler func(ctx ToolContext, params json.RawMessage) (interface{}, *ErrorObj)

// ToolResultText wraps a raw tool result into the MCP content shape that the
// official SDK clients validate against.
//
// Handlers return plain maps (e.g. {"status":"completed","findings":[...]}),
// but CallToolResultSchema on the client side requires a `content` array and
// strips unknown fields — so a raw map is delivered to the model as empty
// output. Serializing the payload into a text block fixes that.
//
// Results that already carry a `content` field pass through untouched.
func ToolResultText(result interface{}) interface{} {
	if result == nil {
		return map[string]interface{}{
			"content": []interface{}{},
			"isError": false,
		}
	}
	if m, ok := result.(map[string]interface{}); ok {
		if _, has := m["content"]; has {
			return m
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return map[string]interface{}{
			"content": []interface{}{map[string]interface{}{
				"type": "text",
				"text": fmt.Sprintf("tool result serialization error: %v", err),
			}},
			"isError": true,
		}
	}
	return map[string]interface{}{
		"content": []interface{}{map[string]interface{}{
			"type": "text",
			"text": string(data),
		}},
		"isError": false,
	}
}

type ToolContext struct {
	MemoryDir   string
	SessionID   string
	RunID       string
	OperationID string
	Scope       *ScopeSnapshot
	Log         func(format string, args ...interface{})
	Ctx         context.Context
}

type ScopeSnapshot struct {
	Domains  []string `json:"domains,omitempty"`
	CIDRs    []string `json:"cidrs,omitempty"`
	Excluded []string `json:"excluded,omitempty"`
	MaxRPS   int      `json:"maxRPS,omitempty"`
	SafeMode *bool    `json:"safeMode,omitempty"`
}

func BoolPtr(b bool) *bool { return &b }
