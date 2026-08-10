package trap

import (
	"fmt"
	"log/slog"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type Factory func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error)

var Registry = map[string]Factory{
	"ssh": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewSSH(cfg, logger, m, limiter, alerter)
	},
	"http": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewHTTP(cfg, logger, m, limiter, alerter), nil
	},
	"mysql": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewMySQL(cfg, logger, m, limiter, alerter), nil
	},
	"rdp": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewRDP(cfg, logger, m, limiter, alerter), nil
	},
	"vnc": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewVNC(cfg, logger, m, limiter, alerter), nil
	},
	"mqtt": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewMQTT(cfg, logger, m, limiter, alerter), nil
	},
	"modbus": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewModbus(cfg, logger, m, limiter, alerter), nil
	},
	"ldap": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewLDAP(cfg, logger, m, limiter, alerter), nil
	},
	"smb": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewSMB(cfg, logger, m, limiter, alerter), nil
	},
	"socks5": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewSOCKS5(cfg, logger, m, limiter, alerter), nil
	},
	"postgres": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewPostgres(cfg, logger, m, limiter, alerter), nil
	},
	"mssql": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewMSSQL(cfg, logger, m, limiter, alerter), nil
	},
	"oracle": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewOracle(cfg, logger, m, limiter, alerter), nil
	},
	"ftp": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewFTP(cfg, logger, m, limiter, alerter), nil
	},
	"telnet": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewTelnet(cfg, logger, m, limiter, alerter), nil
	},
	"redis": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewRedis(cfg, logger, m, limiter, alerter), nil
	},
	"memcached": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewMemcached(cfg, logger, m, limiter, alerter), nil
	},
	"pop3": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewPOP3(cfg, logger, m, limiter, alerter), nil
	},
	"imap": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewIMAP(cfg, logger, m, limiter, alerter), nil
	},
	"irc": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewIRC(cfg, logger, m, limiter, alerter), nil
	},
	"smtp": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewSMTP(cfg, logger, m, limiter, alerter), nil
	},
	"elasticsearch": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewElasticsearch(cfg, logger, m, limiter, alerter), nil
	},
	"httpproxy": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewHTTPProxy(cfg, logger, m, limiter, alerter), nil
	},
	"dns": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewDNS(cfg, logger, m, limiter, alerter), nil
	},
	"snmp": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewSNMP(cfg, logger, m, limiter, alerter), nil
	},
	"sip": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewSIP(cfg, logger, m, limiter, alerter), nil
	},
	"ntp": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (Trap, error) {
		return NewNTP(cfg, logger, m, limiter, alerter), nil
	},
}

func CreateTraps(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) ([]Trap, error) {
	var traps []Trap
	for _, name := range cfg.EnabledTraps() {
		factory, ok := Registry[name]
		if !ok {
			return nil, fmt.Errorf("unknown trap: %s", name)
		}
		t, err := factory(cfg, logger, m, limiter, alerter)
		if err != nil {
			return nil, fmt.Errorf("creating %s trap: %w", name, err)
		}
		traps = append(traps, t)
	}
	return traps, nil
}
