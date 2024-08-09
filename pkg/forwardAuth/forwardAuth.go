package forwardAuth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/config"
)

const (
	realIpHeader  = "X-Real-Ip"
	forwardHeader = "X-Forwarded-For"
	authHeader    = "X-Api-Key"
	bouncerRoute  = "v1/decisions"
)

type Decision struct {
	Id        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

type ForwardAuth struct {
	Cfg    config.Config
	Client *http.Client
	IPs    []net.IP
}

func NewForwardAuth(cfg config.Config) *ForwardAuth {
	return &ForwardAuth{
		Cfg: cfg,
		Client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
			Timeout: 5 * time.Second,
		},
		IPs: []net.IP{
			net.ParseIP("10.0.0.0"),
			net.ParseIP("10.255.255.255"),
			net.ParseIP("172.16.0.0"),
			net.ParseIP("172.31.255.255"),
			net.ParseIP("192.168.0.0"),
			net.ParseIP("192.168.255.255"),
		},
	}
}

func (f *ForwardAuth) isIpAuthorized(clientIP string) (bool, error) {
	decisionUrl := url.URL{
		Scheme:   f.Cfg.BouncerScheme,
		Host:     f.Cfg.BouncerHost,
		Path:     bouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", clientIP),
	}
	req, err := http.NewRequest(http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add(authHeader, f.Cfg.BouncerApiKey)
	slog.Debug("Requesting Crowdsec's decision Local API", "url", decisionUrl.String(), "method", http.MethodGet)

	resp, err := f.Client.Do(req)
	if err != nil || resp.StatusCode == http.StatusForbidden {
		return false, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("An error occurred while closing body reader", "error", err.Error())
		}
	}(resp.Body)
	reqBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if bytes.Equal(reqBody, []byte("null")) {
		slog.Debug("No decision for IP. Accepting", "clientIP", clientIP)
		return true, nil
	}

	slog.Debug("Found Crowdsec's decision(s), evaluating ...", "reqBody", string(reqBody))
	var decisions []Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		return false, err
	}

	return len(decisions) == 0, nil
}

func (f *ForwardAuth) ignoreIP(ip string) bool {
	pIp := net.ParseIP(ip)

	return pIp.To4() == nil ||
		(bytes.Compare(pIp, f.IPs[0]) >= 0 && bytes.Compare(pIp, f.IPs[1]) <= 0) ||
		(bytes.Compare(pIp, f.IPs[2]) >= 0 && bytes.Compare(pIp, f.IPs[3]) <= 0) ||
		(bytes.Compare(pIp, f.IPs[4]) >= 0 && bytes.Compare(pIp, f.IPs[5]) <= 0)
}

func (f *ForwardAuth) getClientIp(r *http.Request) string {
	for _, key := range []string{f.Cfg.ClientIPHeader, realIpHeader, forwardHeader} {
		ip := r.Header.Get(key)
		if ip != "" && !f.ignoreIP(ip) {
			return ip
		}
	}

	return r.RemoteAddr
}

func (f *ForwardAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := f.getClientIp(r)

	slog.Debug("Handling forwardAuth request",
		"ClientIP", clientIP,
		"RemoteAddr", r.RemoteAddr,
		forwardHeader, r.Header[forwardHeader],
		realIpHeader, r.Header[realIpHeader])

	isAuthorized, err := f.isIpAuthorized(clientIP)
	if err != nil {
		slog.Warn("An error occurred while checking IP", "clientIP", clientIP, "error", err.Error())
		w.WriteHeader(f.Cfg.BanResponseCode)
		w.Write([]byte(f.Cfg.BanResponseMsg))
	}
	if !isAuthorized {
		w.WriteHeader(f.Cfg.BanResponseCode)
		w.Write([]byte(f.Cfg.BanResponseMsg))
	}
	w.WriteHeader(http.StatusOK)
}
