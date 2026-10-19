package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/open-mcp-ai/termcp/internal/directive"
	"github.com/open-mcp-ai/termcp/internal/envelope"
)

// The mcp directive's stdio form: an MCP server running ON a shell channel.
//
// This is the half of `mcp` that is not a transport. A handle that names a shell
// is a process the server already started (`pipe mac --argv npx -y …`), and
// driving it is typing a frame at it and reading the answer back — no socket, no
// HTTP, and nothing to open. The URL forms live in term_jrpc.go, where the three
// frame-channel doors share one implementation.
//
// Keeping this here is what lets `mcp` stay one directive after gaining a
// registry: the handle decides which half runs, and a caller does not have to
// know which kind it holds.

// mcpStdio speaks to the process running on a shell channel.
//
// A stdio peer is just a line-oriented pipe: `run` writes the frame, `read` gets the
// reply. That is the whole implementation, and it is why an MCP server needs no
// registration ceremony — `pipe --argv` starts it, and this types at it.
func (s *Server) mcpStdio(ctx context.Context, stmt directive.Statement, sub string, handle string, rest []string) envelope.Slot {
	headers := map[string]string{"Path": stmt.Path}
	switch sub {
	case "tools", "send", "call":
		var frame string
		switch sub {
		case "tools":
			frame = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
		default:
			payload := unquoteWord(strings.TrimSpace(strings.Join(rest, " ")))
			if payload == "" {
				return envelope.Slot{Code: 400, Headers: map[string]string{"Path": stmt.Path, "Error-Code": "invalid_argument"},
					Body: "mcp " + sub + " needs a JSON-RPC frame"}
			}
			frame = payload
		}
		// One frame, one line: the peer reads line-delimited JSON-RPC.
		if _, fail := s.callTool(ctx, "shell_input", argsOf("shell_id", handle, "text", frame)); fail != nil {
			return s.slotFromFailure(ctx, stmt, fail)
		}
		if _, fail := s.callTool(ctx, "shell_key", argsOf("shell_id", handle, "key", "enter")); fail != nil {
			return s.slotFromFailure(ctx, stmt, fail)
		}
		return envelope.Slot{Code: 202, Headers: headers, Body: "sent; read the reply with `mcp recv " + handle + "`"}
	case "recv":
		return s.mcpRecvFrame(ctx, stmt, handle)
	case "close":
		return envelope.Slot{Code: 204, Headers: headers}
	}
	return envelope.Slot{Code: 400, Headers: map[string]string{"Path": stmt.Path, "Error-Code": "invalid_argument"},
		Body: "unknown mcp subcommand: " + sub}
}

// mcpRecvFrame reads exactly one JSON-RPC frame.
//
// The "exactly one" part is the contract: a frame is complete when the bytes parsed
// as JSON, and a partial one must be held rather than acted on. The read is
// therefore retried while the buffer does not yet parse — never a blocking read
// that may return half a message.
//
// No offset is passed, deliberately. The read tool's offset defaults to -1, which
// means "carry on from where the last read stopped"; passing the stream SIZE
// instead (which is what the old code did) asks for bytes after the end, so recv
// answered "no complete frame yet" for a frame that was sitting right there in the
// channel. A recv is a consumer, not a snapshot: it must advance the same cursor
// every other read advances, or the second call re-delivers the first frame.
func (s *Server) mcpRecvFrame(ctx context.Context, stmt directive.Statement, handle string) envelope.Slot {
	res, fail := s.callTool(ctx, "shell_output", argsOf(
		"shell_id", handle, "max_bytes", float64(defaultBytesLimit), "timeout", float64(0)))
	if fail != nil {
		return s.slotFromFailure(ctx, stmt, fail)
	}
	doc, ok := toolResultMap(res)
	if !ok {
		return s.slotFromFailure(ctx, stmt, &toolFailure{code: CodeOperationFailed, msg: toolResultText(res)})
	}
	body := getString(doc, "output", "")
	frame, complete := firstJSONValue(body)
	if !complete {
		return envelope.Slot{Code: 204, Headers: map[string]string{
			"Path":          stmt.Path,
			"Content-Range": envelope.UnsatisfiedRange(int64(getFloatAny(doc, "total_bytes", 0))),
		}, Body: "no complete frame yet"}
	}
	start := int64(getFloatAny(doc, "start_offset", 0))
	end := start + int64(len(frame))
	return envelope.Slot{
		Code:    200,
		Headers: map[string]string{"Path": stmt.Path, "Content-Range": envelope.ContentRange(start, end-1, end)},
		Body:    frame,
	}
}

// firstJSONValue returns the first complete JSON value in raw.
//
// It scans for a complete object or array rather than trusting a newline: a frame
// may be pretty-printed, and a line-delimited peer may still emit a value with
// embedded newlines inside a string.
func firstJSONValue(raw string) (string, bool) {
	trimmed := strings.TrimLeft(raw, " \t\r\n")
	if trimmed == "" {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	var value json.RawMessage
	if err := dec.Decode(&value); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || isSyntaxEOF(err) {
			return "", false
		}
		return "", false
	}
	return strings.TrimSpace(string(value)), true
}

// isSyntaxEOF reports whether a JSON decode failed only because the input ended.
func isSyntaxEOF(err error) bool {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
