package forwardAuth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/cache"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/config"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/limiter"
)

const (
	realIpHeader    = "X-Real-Ip"
	forwardHeader   = "X-Forwarded-For"
	methodHeader    = "X-Forwarded-Method"
	hostHeader      = "X-Forwarded-Host"
	uriHeader       = "X-Forwarded-Uri"
	countryHeader   = "Cf-Ipcountry"
	userAgentHeader = "User-Agent"
	authHeader      = "X-Api-Key"
	bouncerRoute    = "v1/decisions"
	allowed         = "Allowed"
	denied          = "Denied"
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
	Cfg              config.Config
	Client           *http.Client
	IPs              []net.IP
	Requests         int
	Cache            cache.Cache
	Limiter          limiter.Limiter
	AllowedCountries []string
	UserRegexp       *regexp.Regexp
}

func NewForwardAuth(cfg config.Config, c cache.Cache, l limiter.Limiter) *ForwardAuth {
	fa := &ForwardAuth{
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
		Cache:            c,
		Limiter:          l,
		AllowedCountries: strings.Split(cfg.AllowedCountries, ","),
		UserRegexp:       regexp.MustCompile(`[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}`),
	}
	if len(fa.AllowedCountries) == 1 && fa.AllowedCountries[0] == "" {
		fa.AllowedCountries = []string{}
	}
	return fa
}

func (f *ForwardAuth) isIpAuthorized(ctx context.Context, clientIP string) (bool, time.Duration, error) {
	decisionUrl := url.URL{
		Scheme:   f.Cfg.BouncerScheme,
		Host:     f.Cfg.BouncerHost,
		Path:     bouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", clientIP),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		return false, time.Duration(0), err
	}
	req.Header.Add(authHeader, f.Cfg.BouncerApiKey)
	slog.Debug("Requesting Crowdsec's decision Local API", "url", decisionUrl.String(), "method", http.MethodGet)

	resp, err := f.Client.Do(req)
	if err != nil || resp.StatusCode == http.StatusForbidden {
		return false, time.Duration(0), err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("An error occurred while closing body reader", "error", err.Error())
		}
	}(resp.Body)
	reqBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, time.Duration(0), err
	}
	if bytes.Equal(reqBody, []byte("null")) {
		slog.Debug("No decision for IP. Accepting", "clientIP", clientIP)
		return true, time.Duration(0), nil
	}

	slog.Debug("Found Crowdsec's decision(s), evaluating ...", "reqBody", string(reqBody))
	var decisions []Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		return false, time.Duration(0), err
	}

	dur := time.Duration(0)
	for _, d := range decisions {
		cDur, err := time.ParseDuration(d.Duration)
		if err != nil {
			return false, dur, err
		}
		if cDur > dur {
			dur = cDur
		}
	}

	return len(decisions) == 0, dur, nil
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

	return strings.Split(r.RemoteAddr, ":")[0]
}

func (f *ForwardAuth) logAccess(r *http.Request, ip string, statusCode string, start time.Time) {
	user := "-"
	if user != "" {
		s := f.UserRegexp.FindString(r.Header.Get("Cookie"))
		if s != "" {
			user = s
		}
	}
	userAgent := r.Header.Get(userAgentHeader)
	if userAgent == "" {
		userAgent = "-"
	}
	country := r.Header.Get(f.Cfg.CountryHeader)
	if country == "" {
		country = "unknown"
	}
	length := strconv.FormatInt(r.ContentLength, 10)
	f.Requests++
	duration := strconv.FormatInt(time.Since(start).Milliseconds(), 10)
	fmt.Println(ip, "-", user, "["+time.Now().Format("02/Jan/2006:15:04:05 -0700")+"]", "\""+r.Header.Get(methodHeader)+" "+r.Header.Get(uriHeader)+" "+r.Proto+"\"", statusCode, length, "\"-\"", "\""+userAgent+"\"", f.Requests, "\""+country+"@"+r.Header.Get(hostHeader)+"\"", "\"-\"", duration+"ms")
}

func (f *ForwardAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := f.getClientIp(r)

	if len(f.AllowedCountries) > 0 && f.Cfg.CountryHeader != "" && !slices.Contains(f.AllowedCountries, r.Header.Get(f.Cfg.CountryHeader)) {
		slog.Debug("Blocked country", "for", r.Header.Get(f.Cfg.CountryHeader))
		f.Reply(w, r, clientIP, start, false)
		return
	}
	if !f.Limiter.Allow(r.Context(), clientIP) {
		slog.Debug("Rate limit hit", "for", clientIP)
		f.Reply(w, r, clientIP, start, false)
		return
	}

	cached, err := f.Cache.Get(r.Context(), clientIP)
	if err == nil && cached != "" {
		slog.Debug("Cache hit", "result", cached)
		if cached == denied {
			f.Reply(w, r, clientIP, start, false)
			return
		}
		if cached == allowed {
			f.Reply(w, r, clientIP, start, true)
			return
		}
	}

	slog.Debug("Handling forwardAuth request",
		"ClientIP", clientIP,
		"RemoteAddr", r.RemoteAddr,
		forwardHeader, r.Header[forwardHeader],
		realIpHeader, r.Header[realIpHeader])

	isAuthorized, d, err := f.isIpAuthorized(r.Context(), clientIP)
	if err != nil {
		slog.Warn("An error occurred while checking IP", "clientIP", clientIP, "error", err.Error())
		f.Reply(w, r, clientIP, start, false)
		return
	}
	if !isAuthorized {
		f.Reply(w, r, clientIP, start, false)
		go f.SetCache(clientIP, denied, d)
		return
	}
	f.Reply(w, r, clientIP, start, true)
}

func (f *ForwardAuth) Reply(w http.ResponseWriter, r *http.Request, clientIP string, start time.Time, allow bool) {
	if allow {
		w.WriteHeader(http.StatusOK)
		f.logAccess(r, clientIP, strconv.Itoa(http.StatusOK), start)
	} else {
		w.WriteHeader(f.Cfg.BanResponseCode)
		w.Write([]byte(f.Cfg.BanResponseMsg))
		f.logAccess(r, clientIP, strconv.Itoa(f.Cfg.BanResponseCode), start)
	}
}

func (f *ForwardAuth) SetCache(key string, value string, duration time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Minute))
	defer cancel()
	f.Cache.SetWithTTL(ctx, key, value, int(duration.Seconds()))
}
