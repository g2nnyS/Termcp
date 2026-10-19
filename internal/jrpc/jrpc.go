// Package jrpc is one JSON-RPC frame channel over two transports.
//
// Write a frame, read frames until the one carrying your id arrives, and keep
// the rest. That loop is the whole protocol, and it is the same loop for a
// socket and for an HTTP endpoint: the transports differ in exactly two places —
// how a frame goes out, and how frames come in — while the id allocation, the
// "a frame with no id is an event, not an answer", the buffer those events land
// in, and the session id HTTP needs and WS does not are shared.
//
// It is one type with a transport field rather than an interface with two
// implementations, because the interface would have one method per transport and
// every caller would still branch on which one it holds.
//
// It speaks JSON-RPC, not MCP. Nothing here knows what `tools/list` or
// `Page.navigate` mean, which is what lets a peer that spells the envelope
// differently work: CDP frames carry no `jsonrpc` field, need no handshake, and
// route by a `sessionId` INSIDE the frame — that is a property of the peer, not
// of this layer, so it is passed through rather than modelled.
package jrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Transport is how frames move.
type Transport int

const (
	// HTTP is the streamable-MCP shape: every frame is a POST, and the answer is
	// either the POST's JSON body or one event on its text/event-stream body. A
	// Mcp-Session-Id handed out by the first reply must ride on every later
	// request; the channel remembers it so no caller has to.
	HTTP Transport = iota

	// WS is the socket shape: frames flow both ways on one connection with no
	// session header and no pairing beyond the id. A peer that pushes events
	// between requests (DevTools) only works here.
	WS
)

func (t Transport) String() string {
	if t == WS {
		return "ws"
	}
	return "http"
}

const (
	// maxFrameBytes caps one reply body, so a peer that never closes its stream
	// cannot spend the process's memory to answer one call.
	maxFrameBytes = 1 << 20

	// maxEvents is how many unmatched frames a channel holds for Recv before the
	// oldest is dropped.
	//
	// ponytail: drop-oldest ring, no per-event subscriber. Events are a debugging
	// and lifecycle aid (waiting for `Page.loadEventFired`), not a log — a reader
	// that misses one can re-ask the peer. Grow this into a real queue when a
	// caller's correctness starts depending on not losing a specific event.
	maxEvents = 256

	// callTimeout bounds a Call when the context carries no deadline of its own.
	// A socket read cannot be interrupted by context cancellation, so without a
	// deadline a silent peer would hang the call — and a hang here is a hang in
	// the agent's turn, the most expensive place to have one.
	callTimeout = 30 * time.Second
)

// ErrClosed reports a call on a closed channel.
var ErrClosed = errors.New("the channel is closed")

// Channel is one open peer.
type Channel struct {
	url       string
	transport Transport
	client    *http.Client

	// mu serialises calls. Both transports need it: gorilla allows one
	// concurrent reader, and an HTTP call's reply must be matched against the
	// events its own stream carried. Concurrent calls against one channel are
	// therefore queued, which is what a request/response peer wants anyway.
	mu   sync.Mutex
	conn *websocket.Conn
	sess string   // Mcp-Session-Id, once a reply carried one
	next int      // next id to hand out
	ev   []string // frames that arrived while a call waited for its own answer
	shut bool
}

// Open connects rawURL, choosing the transport by scheme: http(s) posts one
// frame per request, ws(s) opens a socket.
func Open(ctx context.Context, rawURL string) (*Channel, error) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %s", rawURL)
	}
	c := &Channel{url: rawURL, next: 1, client: &http.Client{}}
	switch u.Scheme {
	case "ws", "wss":
		c.transport = WS
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", rawURL, err)
		}
		c.conn = conn
	case "http", "https":
		c.transport = HTTP
	default:
		return nil, fmt.Errorf("unsupported scheme %q: http(s) posts a frame per request, ws(s) opens a socket", u.Scheme)
	}
	return c, nil
}

// Transport reports how this channel moves frames.
func (c *Channel) Transport() Transport { return c.transport }

// URL is the address the channel was opened on.
func (c *Channel) URL() string { return c.url }

// Call sends frame and returns the reply carrying its id.
//
// An id is allocated when the frame has none, so a caller can write the frame it
// means and not think about numbering. Frames that arrive while waiting and do
// not carry this id are NOT answers — a CDP peer interleaves events with
// replies — so they are buffered for Recv rather than dropped.
func (c *Channel) Call(ctx context.Context, frame map[string]any) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shut {
		return "", ErrClosed
	}
	id, ok := frame["id"]
	if !ok || id == nil {
		id = c.next
		c.next++
		frame["id"] = id
	}
	if c.transport == WS {
		return c.wsCall(ctx, frame, id)
	}
	return c.httpCall(ctx, frame, id)
}

// Send writes frame and returns at once, without waiting for an answer: a
// notification has none, and a caller that wants to poll can ask for it with
// Recv instead of holding a call open.
func (c *Channel) Send(ctx context.Context, frame map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shut {
		return ErrClosed
	}
	if c.transport == WS {
		if err := c.conn.SetWriteDeadline(deadlineOf(ctx)); err != nil {
			return err
		}
		return c.conn.WriteJSON(frame)
	}
	resp, err := c.httpPost(ctx, frame)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFrameBytes))
	if err != nil {
		return err
	}
	// A notification is owed no answer, but a peer that answers anyway must not
	// have its frame dropped on the floor: Send is "do not wait", not "do not
	// look", so whatever came back is buffered for Recv.
	if body := strings.TrimSpace(string(raw)); body != "" {
		c.buffer(body)
	}
	return nil
}

// Recv returns the next buffered frame — one that arrived while a call was
// waiting for its own answer — and false when there is none. It never blocks:
// bytes are only buffered as a side effect of a Call or a Next, so a reader that
// wants new events has to wait for them.
func (c *Channel) Recv() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pop()
}

// Next waits up to the context's deadline for the next frame that is NOT an
// answer to a call, and returns it.
//
// This is what makes recv worth having. An event arrives on its own schedule — a
// page finishing a load fires Page.loadEventFired AFTER Page.navigate answered —
// so a reader that only looks at what a previous call happened to catch sees
// nothing. Next reads the socket itself, so the wait is the caller's window and
// not a guess about how long a peer takes.
//
// On a channel with no push side (HTTP answers per request) it reports "nothing"
// immediately rather than waiting out a deadline that could not be met.
func (c *Channel) Next(ctx context.Context) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shut {
		return "", false
	}
	if frame, ok := c.pop(); ok {
		return frame, true
	}
	if c.transport != WS {
		return "", false
	}
	deadline := deadlineOf(ctx)
	for {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return "", false
		}
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			// A deadline with nothing on the wire is the ordinary answer: the
			// window expired. Reporting it as an error would make every quiet
			// second look like a broken peer.
			return "", false
		}
		payload := strings.TrimSpace(string(raw))
		if payload == "" {
			continue
		}
		if hasID(payload) {
			// An answer to a call that is no longer waiting (or one that arrived
			// between calls) is still data: keep it for the next Recv.
			c.buffer(payload)
			continue
		}
		return payload, true
	}
}

// pop takes the oldest buffered frame. The caller holds mu.
func (c *Channel) pop() (string, bool) {
	if len(c.ev) == 0 {
		return "", false
	}
	frame := c.ev[0]
	c.ev = c.ev[1:]
	return frame, true
}

// Close shuts the channel. A socket is closed with a normal closure frame so the
// peer does not log an abnormal one.
func (c *Channel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shut {
		return nil
	}
	c.shut = true
	c.ev = nil
	if c.conn != nil {
		_ = c.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		return c.conn.Close()
	}
	return nil
}

// wsCall writes one frame and reads until its answer arrives.
func (c *Channel) wsCall(ctx context.Context, frame map[string]any, id any) (string, error) {
	deadline := deadlineOf(ctx)
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return "", err
	}
	if err := c.conn.WriteJSON(frame); err != nil {
		return "", err
	}
	for {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return "", err
		}
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			return "", err
		}
		payload := strings.TrimSpace(string(raw))
		if carriesID(payload, id) {
			return payload, nil
		}
		c.buffer(payload)
	}
}

// httpCall posts one frame and reads its answer.
//
// The answer is the response body when the peer answers in JSON, and one event
// when it answers on a text/event-stream body: streamable MCP is allowed to do
// either, and a server that streams is the case that used to be handled by
// reading the whole body and searching it afterwards — which hung whenever the
// stream stayed open for notifications, as a spec-compliant one does.
//
// ponytail: one POST sees only the events carried by its own response. Server
// messages that arrive while no request is open need the listening GET stream,
// which this does not open. Add it when a caller depends on unsolicited MCP
// notifications; a request/response peer (and CDP, which uses a socket) does not.
func (c *Channel) httpCall(ctx context.Context, frame map[string]any, id any) (string, error) {
	resp, err := c.httpPost(ctx, frame)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxFrameBytes))
		return string(raw), fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	if !isEventStream(resp.Header.Get("Content-Type")) {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFrameBytes))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	br := bufio.NewReader(io.LimitReader(resp.Body, maxFrameBytes))
	for {
		payload, err := readEvent(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("the event stream ended before the reply to id %v arrived", id)
			}
			return "", err
		}
		if carriesID(payload, id) {
			return payload, nil
		}
		c.buffer(payload)
	}
}

// httpPost sends one frame and hands back the response, whose body is still
// open. The caller closes it.
func (c *Channel) httpPost(ctx context.Context, frame map[string]any) (*http.Response, error) {
	body, err := json.Marshal(frame)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.sess != "" {
		req.Header.Set("Mcp-Session-Id", c.sess)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sess = sid
	}
	return resp, nil
}

// buffer keeps an unmatched frame for Recv, dropping the oldest past the cap.
func (c *Channel) buffer(frame string) {
	if frame == "" {
		return
	}
	c.ev = append(c.ev, frame)
	if len(c.ev) > maxEvents {
		c.ev = c.ev[len(c.ev)-maxEvents:]
	}
}

// deadlineOf is the read/write deadline for one call: the context's own, or the
// default cap when it has none.
func deadlineOf(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(callTimeout)
}

// carriesID reports whether payload is a JSON-RPC message whose id is want.
//
// Ids are compared by their text rather than by type because a peer may echo `1`
// where the caller sent `1`, and a JSON-RPC peer is free to answer a numeric id
// as a string; refusing that would be a protocol-lawyer's answer to a question
// nobody asked. A message with no id is an EVENT, never an answer.
func carriesID(payload string, want any) bool {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal([]byte(payload), &probe); err != nil {
		return false
	}
	if len(probe.ID) == 0 || bytes.Equal(probe.ID, []byte("null")) {
		return false
	}
	return unquoteID(string(probe.ID)) == unquoteID(jsonText(want))
}

// hasID reports whether payload is a request or a response rather than an
// event: an event is the one shape with no id.
func hasID(payload string) bool {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal([]byte(payload), &probe); err != nil {
		return false
	}
	return len(probe.ID) != 0 && !bytes.Equal(probe.ID, []byte("null"))
}

// unquoteID strips the JSON quotes off a string id, so `"7"` and `7` compare
// equal.
func unquoteID(s string) string { return strings.Trim(s, `"`) }

// jsonText renders an id the way it went out on the wire.
func jsonText(v any) string {
	if s, ok := v.(string); ok {
		raw, _ := json.Marshal(s)
		return string(raw)
	}
	return fmt.Sprint(v)
}

// isEventStream reports whether a Content-Type is an SSE body.
func isEventStream(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}

// readEvent reads one complete `data:` payload from an SSE body.
//
// Multi-line data is joined with newlines, which is what the spec says and what
// a pretty-printed JSON frame produces; a comment line (`:keepalive`) is skipped
// rather than concatenated, which is what makes a long-lived stream usable.
func readEvent(br *bufio.Reader) (string, error) {
	var data strings.Builder
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			if payload, ok := sseDataLine(line); ok {
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(payload)
			}
		} else if data.Len() > 0 {
			// The blank line that ends an event.
			return strings.TrimSpace(data.String()), nil
		}
		if err != nil {
			if data.Len() == 0 {
				return "", err
			}
			return strings.TrimSpace(data.String()), nil
		}
	}
}

// sseDataLine returns the payload of a `data:` line.
func sseDataLine(line string) (string, bool) {
	payload, ok := strings.CutPrefix(line, "data:")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(payload), true
}
