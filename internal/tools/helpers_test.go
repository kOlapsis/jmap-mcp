package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mikluko/jmap"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kOlapsis/jmap-mcp/internal/mailview"
)

type staticBackend struct {
	accounts []*Account
	links    []mailview.Attachment
}

func (b *staticBackend) Accounts(context.Context) ([]*Account, error) { return b.accounts, nil }

func (b *staticBackend) SetDefault(_ context.Context, email string) error {
	for _, a := range b.accounts {
		a.Default = a.Email == email
	}
	return nil
}

func (b *staticBackend) AttachmentLink(_ context.Context, _ *mcp.CallToolRequest, _ *Account, _ jmap.ID, att mailview.Attachment) (string, error) {
	b.links = append(b.links, att)
	return "https://bridge.example/attachments/" + att.ID, nil
}

// connect starts the server and an in-memory client; elicit may be nil for a client without elicitation.
func connect(t *testing.T, s *Server, elicit func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	s.Sync(ctx)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{ElicitationHandler: elicit}).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call runs a tool and returns its text content and error flag.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		switch c := c.(type) {
		case *mcp.TextContent:
			b.WriteString(c.Text)
		case *mcp.ImageContent:
			b.WriteString("image:" + c.MIMEType)
		}
	}
	return b.String(), res.IsError
}

// callJSON runs a tool that must succeed and decodes its JSON result.
func callJSON(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any, out any) {
	t.Helper()
	txt, isErr := call(t, cs, name, args)
	if isErr {
		t.Fatalf("%s returned an error: %s", name, txt)
	}
	if err := json.Unmarshal([]byte(txt), out); err != nil {
		t.Fatalf("%s: %v: %s", name, err, txt)
	}
}
