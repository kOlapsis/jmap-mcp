package stdio

import (
	"context"
	"errors"
	"log/slog"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

type manager struct{ onChange func() }

func newManager(*config.Config, *slog.Logger) (*manager, error) {
	return nil, errors.New("not implemented")
}
func (m *manager) Close()                                             {}
func (m *manager) Accounts(context.Context) ([]*tools.Account, error) { return nil, nil }
func (m *manager) SetDefault(context.Context, string) error           { return nil }
func (m *manager) Connect(context.Context, string, bool) (string, error) {
	return "", errors.New("not implemented")
}
