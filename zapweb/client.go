// client.go — the Go zapweb client. It is the reference implementation
// the TS/JS browser client mirrors byte-for-byte: stamp the procedure
// opcode into the message Flags() header, prepend the [reqID][flag]
// correlation prefix, send as one binary WebSocket message, read the
// correlated reply.
//
// Calls are serialized on one connection (a single in-flight request at
// a time, guarded by mu). That is sufficient for the daemon-to-daemon
// and test paths; a browser tab that needs concurrent calls opens the
// connection per call or dials more than one Client.

package zapweb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/coder/websocket"
	zap "github.com/luxfi/zap"
	"github.com/luxfi/zap/zapclient"
)

// Client is a zapweb (ZAP-over-WebSocket) client. Construct with Dial,
// always Close.
type Client struct {
	conn  *websocket.Conn
	mu    sync.Mutex
	reqID uint32
}

// Dial opens a zapweb connection to url (e.g. "ws://host:port/zap" or
// "wss://..."). Caller MUST Close.
func Dial(ctx context.Context, url string) (*Client, error) {
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("zapweb: dial %s: %w", url, err)
	}
	conn.SetReadLimit(1 << 20)
	return &Client{conn: conn}, nil
}

// Close terminates the connection.
func (c *Client) Close() error { return c.conn.Close(websocket.StatusNormalClosure, "") }

// Call invokes procedure with req and returns the reply message. req may
// be nil for parameter-less procedures. A dispatch-level failure on the
// server (unknown procedure / rejected peer / handler error) is returned
// as a Go error; procedure-level status lives inside the reply message
// (same as the native transport).
func (c *Client) Call(ctx context.Context, procedure string, req *zap.Message) (*zap.Message, error) {
	frame, err := encodeRequest(c.nextReqID(), procedure, req)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
		return nil, fmt.Errorf("zapweb: write: %w", err)
	}
	typ, data, err := c.conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("zapweb: read: %w", err)
	}
	if typ != websocket.MessageBinary || len(data) < corrHeader {
		return nil, errors.New("zapweb: malformed reply frame")
	}
	flag := binary.LittleEndian.Uint32(data[4:8])
	body := data[corrHeader:]
	switch flag {
	case FlagErr:
		return nil, fmt.Errorf("zapweb: dispatch error: %s", string(body))
	case uint32(zap.ReqFlagResp):
		if len(body) == 0 {
			return nil, nil
		}
		msg, perr := zap.Parse(body)
		if perr != nil {
			return nil, fmt.Errorf("zapweb: parse reply: %w", perr)
		}
		return msg, nil
	default:
		return nil, fmt.Errorf("zapweb: unexpected reply flag %d", flag)
	}
}

func (c *Client) nextReqID() uint32 {
	c.mu.Lock()
	c.reqID++
	id := c.reqID
	c.mu.Unlock()
	return id
}

// encodeRequest stamps the procedure opcode into the message flags and
// prepends the [reqID][ReqFlagReq] correlation prefix. Mirrors
// zapclient's withFlags so the server's opcode dispatch is identical
// across transports.
func encodeRequest(reqID uint32, procedure string, req *zap.Message) ([]byte, error) {
	op, err := zapclient.ProcedureOpcode(procedure)
	if err != nil {
		return nil, err
	}
	var body []byte
	if req == nil {
		b := zap.NewBuilder(zap.HeaderSize)
		ob := b.StartObject(0)
		ob.FinishAsRoot()
		body = b.FinishWithFlags(op)
	} else {
		body = append([]byte(nil), req.Bytes()...)
		// Flags occupy bytes 6..8 of the ZAP header (zap.go Flags()).
		body[6] = byte(op)
		body[7] = byte(op >> 8)
	}
	out := make([]byte, corrHeader+len(body))
	binary.LittleEndian.PutUint32(out[0:4], reqID)
	binary.LittleEndian.PutUint32(out[4:8], uint32(zap.ReqFlagReq))
	copy(out[corrHeader:], body)
	return out, nil
}
