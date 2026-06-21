package mqtt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// CLIResponse is the parsed JSON response from a device CLI command.
type CLIResponse struct {
	Cmd    string   `json:"cmd"`
	ReqID  string   `json:"req_id,omitempty"`
	OK     bool     `json:"ok"`
	Output []string `json:"output,omitempty"`
	// Pagination fields (firmware v1.4.6+). A command whose output
	// overflows the device publish buffer is split across multiple
	// cli/response messages, each with a 0-indexed Page and a More flag;
	// the final page carries More=false. Pre-1.4.6 firmware omits both
	// and the single message is the whole response. CLIRequest /
	// CLIRequestRaw accumulate pages transparently, so a CLIResponse
	// they return always has Page/More nil and Output holding the
	// concatenated result.
	Page *int  `json:"page,omitempty"`
	More *bool `json:"more,omitempty"`
	// Chunked fs.cat fields (present when offset/length requested)
	Total  *int    `json:"total,omitempty"`
	Offset *int    `json:"offset,omitempty"`
	Length *int    `json:"length,omitempty"`
	Done   *bool   `json:"done,omitempty"`
	Data   *string `json:"data,omitempty"`
}

// awaitPagedCLIResponse reads cli/response payloads off ch and assembles a
// complete CLIResponse. Firmware v1.4.6+ paginates oversized output across
// multiple messages (0-indexed Page, More flag; the final page carries
// More=false). This concatenates each page's Output in Page order and
// returns once the final page and every lower-indexed page have arrived.
// Single-page responses and pre-1.4.6 firmware (no Page/More) return on
// the first message. Pages may arrive out of order - the assembly is
// keyed by Page index, not arrival order. The returned CLIResponse has
// Page/More cleared.
// in: ctx, ch (raw cli/response payload bytes). out: assembled *CLIResponse, error.
func awaitPagedCLIResponse(ctx context.Context, ch <-chan []byte) (*CLIResponse, error) {
	pages := make(map[int][]string)
	var (
		final     CLIResponse
		haveFinal bool
	)
	for {
		select {
		case raw := <-ch:
			var resp CLIResponse
			if err := json.Unmarshal(raw, &resp); err != nil {
				return nil, fmt.Errorf("parse response: %w", err)
			}
			page := 0
			if resp.Page != nil {
				page = *resp.Page
			}
			pages[page] = resp.Output
			// More absent or false marks the last page. Older firmware
			// omits More entirely, so its single message is the final
			// (and only) page.
			if resp.More == nil || !*resp.More {
				final = resp
				haveFinal = true
			}
			if !haveFinal {
				continue
			}
			finalIdx := 0
			if final.Page != nil {
				finalIdx = *final.Page
			}
			combined := make([]string, 0)
			complete := true
			for i := 0; i <= finalIdx; i++ {
				pg, ok := pages[i]
				if !ok {
					complete = false
					break
				}
				combined = append(combined, pg...)
			}
			if !complete {
				continue
			}
			final.Output = combined
			final.Page = nil
			final.More = nil
			return &final, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// cliEnvelope wraps a CLI command payload so the firmware (v1.4.5+) can
// echo req_id back on cli/response for correlation. Older firmware ignores
// unknown fields and runs the command with the envelope JSON as a literal
// arg - so on a mixed-version fleet, the per-device mutex remains the
// load-bearing defence. The firmware unwraps `args` and runs the command
// with that as the raw payload (binary protocols see the same path\n
// content / type\nPEM bytes inside the args string).
type cliEnvelope struct {
	ReqID string `json:"req_id"`
	Args  string `json:"args"`
}

// cliLockFor returns a mutex unique to the given device. Lazily initialised
// so the map never grows beyond devices that actually receive CLI traffic.
// Caller must Lock/Unlock; held for the duration of one CLIRequest.
// in: topic prefix. out: mutex pointer (never nil).
func (c *Client) cliLockFor(topicPrefix string) *sync.Mutex {
	c.cliMu.Lock()
	defer c.cliMu.Unlock()
	if c.cliLocks == nil {
		c.cliLocks = make(map[string]*sync.Mutex)
	}
	m, ok := c.cliLocks[topicPrefix]
	if !ok {
		m = &sync.Mutex{}
		c.cliLocks[topicPrefix] = m
	}
	return m
}

// CLIRequest sends a CLI command to a device via MQTT and waits for the
// response. topicPrefix is the device's full MQTT prefix (e.g.
// "thesada/acme/owb"). command is the CLI command name (e.g.
// "fs.cat", "config.dump"). payload is the command argument (empty string
// for no-arg commands). Context controls the timeout.
//
// Per-device serialization: holds cliLockFor(topicPrefix) for the duration
// of the call so two concurrent CLIRequests against the same device do not
// race on the shared cli/response topic. req_id correlation (firmware
// v1.4.5+) filters out late or retained-replay responses with a different
// id so the second call cannot accidentally consume the first call's
// late reply. Older firmware that ignores req_id still works - the mutex
// alone makes the response unambiguous.
// in: ctx, topicPrefix, command, payload. out: *CLIResponse, error.
func (c *Client) CLIRequest(ctx context.Context, topicPrefix, command, payload string) (*CLIResponse, error) {
	if c.c == nil || !c.c.IsConnected() {
		return nil, errors.New("mqtt client not connected")
	}

	lock := c.cliLockFor(topicPrefix)
	lock.Lock()
	defer lock.Unlock()

	reqID := uuid.NewString()
	env, err := json.Marshal(cliEnvelope{ReqID: reqID, Args: payload})
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	respTopic := topicPrefix + "/cli/response"
	// Buffered well past any realistic page count so the non-blocking
	// tap send below never drops an intermediate page of a paginated
	// response (firmware v1.4.6+).
	ch := make(chan []byte, 64)
	cancel, err := c.RegisterTap(respTopic, func(_ string, p []byte, _ bool, _ byte) {
		// Filter on req_id when present. Firmware v1.4.5+ echoes req_id
		// for every CLI envelope; older firmware omits it. Either is
		// acceptable here - the per-device mutex already guarantees at
		// most one outstanding request, so a response without req_id is
		// always the response we just published.
		var probe struct {
			ReqID string `json:"req_id"`
		}
		_ = json.Unmarshal(p, &probe)
		if probe.ReqID != "" && probe.ReqID != reqID {
			return
		}
		select {
		case ch <- append([]byte(nil), p...):
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("register tap: %w", err)
	}
	defer cancel()

	cmdTopic := topicPrefix + "/cli/" + command
	if err := c.PublishRaw(cmdTopic, env, 0, false); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}

	return awaitPagedCLIResponse(ctx, ch)
}

// CLIRequestRaw sends a CLI command with a raw byte payload (for fs.write
// and fs.append where the payload contains path + newline + binary content).
// Firmware binary handlers read payload as raw bytes and would not parse a
// JSON envelope, so this path does not wrap. The per-device mutex still
// serializes against any concurrent CLIRequest on the same device.
// in: ctx, topicPrefix, command, rawPayload. out: *CLIResponse, error.
func (c *Client) CLIRequestRaw(ctx context.Context, topicPrefix, command string, rawPayload []byte) (*CLIResponse, error) {
	if c.c == nil || !c.c.IsConnected() {
		return nil, errors.New("mqtt client not connected")
	}

	lock := c.cliLockFor(topicPrefix)
	lock.Lock()
	defer lock.Unlock()

	respTopic := topicPrefix + "/cli/response"
	// Buffered well past any realistic page count so the non-blocking
	// tap send below never drops an intermediate page of a paginated
	// response (firmware v1.4.6+).
	ch := make(chan []byte, 64)
	cancel, err := c.RegisterTap(respTopic, func(_ string, p []byte, _ bool, _ byte) {
		select {
		case ch <- append([]byte(nil), p...):
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("register tap: %w", err)
	}
	defer cancel()

	cmdTopic := topicPrefix + "/cli/" + command
	pubPayload := rawPayload
	// SIM7080G modem-native MQTT silently drops +SMSUB: URCs for empty-
	// payload publishes (verified 2026-05-08 against LilyGO vendor reference
	// firmware on the same broker / SIM / cellular session). Substitute "{}"
	// so the URC always fires; firmware binary handlers treat an empty
	// payload the same as missing args.
	if len(pubPayload) == 0 {
		pubPayload = []byte("{}")
	}
	if err := c.PublishRaw(cmdTopic, pubPayload, 0, false); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}

	return awaitPagedCLIResponse(ctx, ch)
}
