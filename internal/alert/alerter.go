package alert

import "context"

type Alerter interface {
	Alert(ctx context.Context, ip string, protocol string, meta map[string]string)
	Close()
}

type NoopAlerter struct{}

func (NoopAlerter) Alert(context.Context, string, string, map[string]string) {}
func (NoopAlerter) Close()                                                   {}
