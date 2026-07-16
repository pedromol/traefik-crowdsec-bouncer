package logger

import (
	"context"
	"fmt"
	"log/slog"
)

type Logger struct{}

func (l Logger) Printf(ctx context.Context, format string, v ...interface{}) {
	slog.Debug(fmt.Sprintf(format, v...))
}
