// Dynamic-security plugin client. Drives the Mosquitto dynsec
// control API (publish JSON commands to $CONTROL/dynamic-security/v1, read
// replies from the matching /response topic) so thesada-app can provision
// per-device clients + per-CN roles at pair time without SSHing into the
// broker host. The broker is assumed to be running the dynsec plugin with
// an "admin" role that allows pub/sub on the control topic tree; the app
// connects as the thesada-app dynsec client with the app-control role.
package mqtt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

const (
	dynsecCommandTopic  = "$CONTROL/dynamic-security/v1"
	dynsecResponseTopic = "$CONTROL/dynamic-security/v1/response"
)

// DynsecACL is one ACL entry attached to a role. Allow=false encodes an
// explicit deny, which takes precedence over any allow on the same topic.
type DynsecACL struct {
	ACLType string `json:"acltype"`
	Topic   string `json:"topic"`
	Allow   bool   `json:"allow"`
}

// DynsecRole is the embedded role reference on a client - only the name
// is required; the role itself is defined separately.
type DynsecRole struct {
	Rolename string `json:"rolename"`
}

// dynsecCommand is the envelope sent on the control topic. CorrelationData
// is echoed back in the matching response so we can demultiplex concurrent
// calls - we use a process-global counter.
type dynsecCommand struct {
	Command         string       `json:"command"`
	Username        string       `json:"username,omitempty"`
	Password        string       `json:"password,omitempty"`
	Clientid        string       `json:"clientid,omitempty"`
	Rolename        string       `json:"rolename,omitempty"`
	Roles           []DynsecRole `json:"roles,omitempty"`
	ACLs            []DynsecACL  `json:"acls,omitempty"`
	TextName        string       `json:"textname,omitempty"`
	TextDescription string       `json:"textdescription,omitempty"`
	CorrelationData string       `json:"correlationData,omitempty"`
}

// dynsecEnvelope wraps a batch. Mosquitto accepts multiple commands but we
// send one at a time to keep error handling simple.
type dynsecEnvelope struct {
	Commands []dynsecCommand `json:"commands"`
}

// dynsecResponseItem mirrors the per-command reply. Error is empty on
// success. Data carries listClients/listRoles output when applicable.
type dynsecResponseItem struct {
	Command         string          `json:"command"`
	Error           string          `json:"error,omitempty"`
	CorrelationData string          `json:"correlationData,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"`
}

type dynsecResponseEnvelope struct {
	Responses []dynsecResponseItem `json:"responses"`
}

// dynsecSeq generates correlation IDs across concurrent callers on the
// same *Client. Reset is fine on process restart - no persistence needed.
var dynsecSeq atomic.Uint64

// sendDynsec publishes one dynsec command and waits for the matching
// response. Returns the response data or an error (broker-side error
// strings are returned verbatim so callers can distinguish "already
// exists" from real failures). ctx bounds the total wait; 5 s is enough
// for a local broker round-trip.
// in: ctx, cmd (CorrelationData is filled in). out: raw data from response, error.
func (c *Client) sendDynsec(ctx context.Context, cmd dynsecCommand) (json.RawMessage, error) {
	if c.c == nil || !c.c.IsConnected() {
		return nil, errors.New("mqtt client not connected")
	}
	cmd.CorrelationData = fmt.Sprintf("thesada-app-%d", dynsecSeq.Add(1))

	ch := make(chan []byte, 1)
	cancel, err := c.RegisterTap(dynsecResponseTopic, func(topic string, p []byte, retained bool, qos byte) {
		select {
		case ch <- append([]byte(nil), p...):
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("register dynsec tap: %w", err)
	}
	defer cancel()

	payload, err := json.Marshal(dynsecEnvelope{Commands: []dynsecCommand{cmd}})
	if err != nil {
		return nil, fmt.Errorf("marshal dynsec cmd: %w", err)
	}
	if err := c.PublishRaw(dynsecCommandTopic, payload, 0, false); err != nil {
		return nil, fmt.Errorf("publish dynsec cmd: %w", err)
	}

	for {
		select {
		case raw := <-ch:
			var env dynsecResponseEnvelope
			if err := json.Unmarshal(raw, &env); err != nil {
				return nil, fmt.Errorf("parse dynsec response: %w", err)
			}
			for _, r := range env.Responses {
				if r.CorrelationData != cmd.CorrelationData {
					continue
				}
				if r.Error != "" {
					return nil, fmt.Errorf("dynsec %s: %s", cmd.Command, r.Error)
				}
				return r.Data, nil
			}
			// Response without matching correlationData - keep waiting.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// IsDynsecAlreadyExists reports whether err is a dynsec "already exists"
// style error. Used by callers that want idempotent create semantics
// (retrying a pair operation after partial failure must not trip on
// the already-present role / client).
// in: err. out: true if "already exists" shaped.
func IsDynsecAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "already exists") || strings.Contains(s, "already has")
}

// CreateDynsecRole creates a role with the given ACLs. Idempotent from the
// caller's perspective: an "already exists" error is surfaced but callers
// typically use IsDynsecAlreadyExists to swallow it.
// in: ctx, role name, ACL list. out: error.
func (c *Client) CreateDynsecRole(ctx context.Context, name string, acls []DynsecACL) error {
	_, err := c.sendDynsec(ctx, dynsecCommand{
		Command:  "createRole",
		Rolename: name,
		ACLs:     acls,
	})
	return err
}

// DeleteDynsecRole removes a role. Safe to call on a role that does not
// exist - caller should inspect the returned error via
// IsDynsecAlreadyExists-style matching if needed.
// in: ctx, role name. out: error.
func (c *Client) DeleteDynsecRole(ctx context.Context, name string) error {
	_, err := c.sendDynsec(ctx, dynsecCommand{
		Command:  "deleteRole",
		Rolename: name,
	})
	return err
}

// CreateDynsecClient creates a client with the given roles. Password may
// be empty for cert-auth clients on the mTLS listener - use_identity_as_username
// maps the TLS CN to the username, and the dynsec plugin authorizes based
// on the client's attached roles.
// in: ctx, username, password (empty for cert-only), role names. out: error.
func (c *Client) CreateDynsecClient(ctx context.Context, username, password string, roles []string) error {
	rs := make([]DynsecRole, 0, len(roles))
	for _, r := range roles {
		rs = append(rs, DynsecRole{Rolename: r})
	}
	_, err := c.sendDynsec(ctx, dynsecCommand{
		Command:  "createClient",
		Username: username,
		Password: password,
		Roles:    rs,
	})
	return err
}

// DeleteDynsecClient removes a client. Any active sessions for that
// username are disconnected by the broker on the next auth check.
// in: ctx, username. out: error.
func (c *Client) DeleteDynsecClient(ctx context.Context, username string) error {
	_, err := c.sendDynsec(ctx, dynsecCommand{
		Command:  "deleteClient",
		Username: username,
	})
	return err
}
