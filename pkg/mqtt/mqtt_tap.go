package mqtt

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// mqttTap is a single subscriber bolted onto the running Client. Sink must
// be non-blocking - implementations are expected to push into a bounded
// channel and drop on back-pressure. The matcher honors MQTT `+` and `#`
// wildcards, same rules as paho.
type mqttTap struct {
	id      uint64
	pattern string
	matcher func(topic string) bool
	sink    TapSink
}

// TapSink is the callback a /admin/mqtt websocket handler registers to
// receive live MQTT messages that match its pattern.
type TapSink func(topic string, payload []byte, retained bool, qos byte)

// ErrTapPattern is returned by RegisterTap when the pattern does not compile
// into a valid MQTT topic filter.
var ErrTapPattern = errors.New("invalid mqtt topic pattern")

// compileMQTTMatcher turns an MQTT topic filter (with + and # wildcards)
// into a function that tests whether a published topic matches.
//
// Validation follows MQTT 3.1.1 section 4.7:
//   - The filter must not be empty.
//   - `+` (single-level wildcard) must occupy an entire level on its own,
//     bounded by `/`, string start, or string end. Segments that mix `+` with
//     literal characters (e.g. "+foo", "bar+", "a+b") are rejected.
//   - `#` (multi-level wildcard) must be the last character in the filter.
//     It must either be the entire filter ("# ") or be its own level preceded
//     by a `/` (e.g. "thesada/#"). A `#` embedded in a segment with other
//     characters (e.g. "foo#", "a#b") or appearing before the end of the
//     filter (e.g. "#/bar") is rejected.
//   - Consecutive level separators ("//") produce empty segments. These are
//     valid in topic names per the spec but are rejected here as they are
//     almost always an operator mistake when constructing a filter at runtime.
//
// in: pattern string. out: matcher func, error if the pattern is malformed.
func compileMQTTMatcher(pattern string) (func(string) bool, error) {
	if pattern == "" {
		return nil, fmt.Errorf("%w: filter must not be empty", ErrTapPattern)
	}
	parts := strings.Split(pattern, "/")
	for i, p := range parts {
		switch {
		case p == "":
			// The very first segment may be empty only for a leading-slash
			// filter (e.g. "/sport"), which is spec-valid. An empty segment
			// anywhere else (from "//") is almost always a bug.
			if i != 0 {
				return nil, fmt.Errorf("%w: empty segment at level %d (consecutive '/' separators are not allowed in filters)", ErrTapPattern, i)
			}
		case p == "#":
			if i != len(parts)-1 {
				return nil, fmt.Errorf("%w: '#' at level %d is not the last level - '#' must only appear as the final segment (MQTT 3.1.1 s4.7.1)", ErrTapPattern, i)
			}
		case strings.Contains(p, "#"):
			return nil, fmt.Errorf("%w: level %d %q mixes '#' with other characters - '#' must occupy an entire level on its own", ErrTapPattern, i, p)
		case strings.Contains(p, "+"):
			if p != "+" {
				return nil, fmt.Errorf("%w: level %d %q mixes '+' with other characters - '+' must occupy an entire level on its own", ErrTapPattern, i, p)
			}
		}
	}
	return func(topic string) bool {
		tp := strings.Split(topic, "/")
		for i, p := range parts {
			if p == "#" {
				return true
			}
			if i >= len(tp) {
				return false
			}
			if p == "+" {
				continue
			}
			if p != tp[i] {
				return false
			}
		}
		return len(tp) == len(parts)
	}, nil
}

// RegisterTap attaches a TapSink to the running client. Pattern is an MQTT
// wildcard filter (+ and #). Returns a cancel func the caller runs to
// detach; always call it via defer on the handler shutdown path.
// in: pattern, sink. out: cancel, error.
func (c *Client) RegisterTap(pattern string, sink TapSink) (func(), error) {
	matcher, err := compileMQTTMatcher(pattern)
	if err != nil {
		return nil, err
	}
	id := c.tapSeq.Add(1)
	tap := &mqttTap{id: id, pattern: pattern, matcher: matcher, sink: sink}
	c.mu.Lock()
	if c.taps == nil {
		c.taps = make(map[uint64]*mqttTap)
	}
	c.taps[id] = tap
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.taps, id)
		c.mu.Unlock()
	}, nil
}

// fanoutTaps dispatches one inbound MQTT message to every tap whose pattern
// matches. Runs in the paho callback goroutine; sinks must be fast and
// non-blocking (push into a channel + drop on full).
// in: topic, payload, retained flag, qos. out: none.
func (c *Client) fanoutTaps(topic string, payload []byte, retained bool, qos byte) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, t := range c.taps {
		if t.matcher(topic) {
			t.sink(topic, payload, retained, qos)
		}
	}
}

// PublishRaw forwards a publish through the shared paho client without any
// topic validation - that's the caller's responsibility (the /admin/mqtt
// handler enforces the tenant prefix guard and the audit log).
// in: topic, payload, qos, retain. out: error from paho.
func (c *Client) PublishRaw(topic string, payload []byte, qos byte, retain bool) error {
	if c.c == nil || !c.c.IsConnected() {
		return errors.New("mqtt client not connected")
	}
	t := c.c.Publish(topic, qos, retain, payload)
	t.WaitTimeout(5 * time.Second)
	return t.Error()
}
