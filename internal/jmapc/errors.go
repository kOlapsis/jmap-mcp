package jmapc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/mikluko/jmap"
)

// ErrUnauthorized means the mail server rejected the credentials.
var ErrUnauthorized = errors.New("the mail server rejected the authorization; reconnect the account")

// MethodError is a JMAP method-level error (RFC 8620 §3.6.2).
type MethodError struct {
	Type        string
	Description string
}

func (e *MethodError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("jmap %s: %s", e.Type, e.Description)
	}
	return "jmap " + e.Type
}

// HTTPError is a request-level failure, decoded from an RFC 7807 problem when present.
type HTTPError struct {
	Status int
	Type   string
	Detail string
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("jmap: HTTP %d", e.Status)
	if e.Type != "" {
		msg += " " + e.Type
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

func httpError(resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	e := &HTTPError{Status: resp.StatusCode}
	if strings.Contains(resp.Header.Get("Content-Type"), "json") {
		var p struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&p) == nil {
			e.Type, e.Detail = p.Type, p.Detail
		}
	}
	return e
}

// SetErrors flattens the per-record failures of a /set response, or returns nil.
func SetErrors(groups ...map[jmap.ID]*jmap.SetError) error {
	var msgs []string
	for _, g := range groups {
		for id, se := range g {
			msg := string(id) + ": " + se.Type
			if se.Description != nil {
				msg += " (" + *se.Description + ")"
			}
			if se.Properties != nil {
				msg += " properties=" + strings.Join(*se.Properties, ",")
			}
			msgs = append(msgs, msg)
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	sort.Strings(msgs)
	return errors.New("jmap: " + strings.Join(msgs, "; "))
}
