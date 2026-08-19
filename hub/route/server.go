package route

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/cors"
	"github.com/metacubex/chi/middleware"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

var (
	uiPath = ""

	// serverMu serializes complete external-controller generations. Listener
	// creation and registration happen while it is held; replacing or shutting
	// down a generation closes both its http.Server and its raw listener, then
	// waits for every Serve goroutine before a newer generation can be created.
	// A goroutine which has not reached Server.Serve yet is therefore still
	// owned and closed by the generation that launched it.
	serverMu         sync.Mutex
	serverGeneration uint64
	serverWG         sync.WaitGroup
	httpServer       *managedServer
	tlsServer        *managedServer
	unixServer       *managedServer
	pipeServer       *managedServer

	embedMode = false
)

type managedServer struct {
	generation uint64
	logPrefix  string
	server     *http.Server
	listener   net.Listener
}

type serveFunc func(*http.Server, net.Listener) error

func SetEmbedMode(embed bool) {
	embedMode = embed
}

type Traffic struct {
	Up        int64 `json:"up"`
	Down      int64 `json:"down"`
	UpTotal   int64 `json:"upTotal"`
	DownTotal int64 `json:"downTotal"`
}

type Memory struct {
	Inuse   uint64 `json:"inuse"`
	OSLimit uint64 `json:"oslimit"` // maybe we need it in the future
}

type Config struct {
	Addr           string
	TLSAddr        string
	UnixAddr       string
	PipeAddr       string
	RoutingMark    int
	Secret         string
	Certificate    string
	PrivateKey     string
	ClientAuthType string
	ClientAuthCert string
	EchKey         string
	DohServer      string
	IsDebug        bool
	Cors           Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

func (c Cors) Apply(r chi.Router) {
	r.Use(cors.New(cors.Options{
		AllowedOrigins:      c.AllowOrigins,
		AllowedMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:      []string{"Content-Type", "Authorization"},
		AllowPrivateNetwork: c.AllowPrivateNetwork,
		MaxAge:              300,
	}).Handler)
}

func ReCreateServer(cfg *Config) {
	reCreateServer(cfg, func(server *http.Server, listener net.Listener) error {
		return server.Serve(listener)
	})
}

// reCreateServer accepts an injectable Serve boundary so tests can hold a
// goroutine between listener registration and Server.Serve deterministically.
// Production always supplies Server.Serve directly through ReCreateServer.
func reCreateServer(cfg *Config, serve serveFunc) {
	serverMu.Lock()
	defer serverMu.Unlock()

	// Invalidate first. stopServersLocked waits for every goroutine belonging to
	// the old generation before any listener for this generation is created.
	serverGeneration++
	stopServersLocked()
	generation := serverGeneration

	httpServer = prepareHTTPServer(cfg, generation)
	tlsServer = prepareTLSServer(cfg, generation)
	unixServer = prepareUnixServer(cfg, generation)
	if inbound.SupportNamedPipe {
		pipeServer = preparePipeServer(cfg, generation)
	}

	for _, current := range []*managedServer{httpServer, tlsServer, unixServer, pipeServer} {
		if current == nil {
			continue
		}
		serverWG.Add(1)
		go serveManagedServer(current, serve)
	}
}

func serveManagedServer(current *managedServer, serve serveFunc) {
	defer serverWG.Done()
	if err := serve(current.server, current.listener); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.Errorln("%s (generation %d): %s", current.logPrefix, current.generation, err)
	}
}

func stopServersLocked() {
	servers := []*managedServer{httpServer, tlsServer, unixServer, pipeServer}
	httpServer = nil
	tlsServer = nil
	unixServer = nil
	pipeServer = nil

	for _, current := range servers {
		if current == nil {
			continue
		}
		// Close marks Server as shut down even if Serve has not started yet.
		// Closing the raw listener as well releases the bound endpoint in that
		// pre-Serve window; Serve will then return ErrServerClosed when scheduled.
		_ = current.server.Close()
		_ = current.listener.Close()
	}
	serverWG.Wait()
}

// Shutdown synchronously closes every external-controller server and raw
// listener, then waits for all Serve goroutines in that generation. An
// embedding host can therefore StopCore→StartCore back to back safely.
func Shutdown() {
	serverMu.Lock()
	defer serverMu.Unlock()
	serverGeneration++
	stopServersLocked()
}

func SetUIPath(path string) {
	uiPath = C.Path.Resolve(path)
}

func router(isDebug bool, secret string, dohServer string, cors Cors) *chi.Mux {
	r := chi.NewRouter()
	cors.Apply(r)
	if isDebug {
		r.Mount("/debug", func() http.Handler {
			r := chi.NewRouter()
			r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
				debug.FreeOSMemory()
			})
			handler := middleware.Profiler
			r.Mount("/", handler())
			return r
		}())
	}
	r.Group(func(r chi.Router) {
		if secret != "" {
			r.Use(authentication(secret))
		}
		r.Get("/", hello)
		r.Get("/logs", getLogs)
		r.Get("/traffic", traffic)
		r.Get("/memory", memory)
		r.Get("/version", version)
		r.Mount("/configs", configRouter())
		r.Mount("/proxies", proxyRouter())
		r.Mount("/group", groupRouter())
		r.Mount("/rules", ruleRouter())
		r.Mount("/connections", connectionRouter())
		r.Mount("/providers/proxies", proxyProviderRouter())
		r.Mount("/providers/rules", ruleProviderRouter())
		r.Mount("/cache", cacheRouter())
		r.Mount("/dns", dnsRouter())
		r.Mount("/storage", storageRouter())
		if !embedMode { // disallow restart in embed mode
			r.Mount("/restart", restartRouter())
		}
		r.Mount("/upgrade", upgradeRouter())
		addExternalRouters(r)

	})

	if uiPath != "" {
		r.Group(func(r chi.Router) {
			fs := http.StripPrefix("/ui", http.FileServer(http.Dir(uiPath)))
			r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
			r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
				fs.ServeHTTP(w, r)
			})
		})
	}
	if len(dohServer) > 0 && dohServer[0] == '/' {
		r.Mount(dohServer, dohRouter())
	}

	return r
}

func prepareHTTPServer(cfg *Config, generation uint64) *managedServer {
	if len(cfg.Addr) == 0 {
		return nil
	}
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(cfg.RoutingMark)
	listener, err := lc.Listen(context.Background(), "tcp", cfg.Addr)
	if err != nil {
		log.Errorln("External controller listen error: %s", err)
		return nil
	}
	log.Infoln("RESTful API listening at: %s", listener.Addr().String())

	return &managedServer{
		generation: generation,
		logPrefix:  "External controller serve error",
		server: &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		},
		listener: listener,
	}
}

func prepareTLSServer(cfg *Config, generation uint64) *managedServer {
	if len(cfg.TLSAddr) == 0 {
		return nil
	}
	certLoader, err := ca.NewTLSKeyPairLoader(cfg.Certificate, cfg.PrivateKey)
	if err != nil {
		log.Errorln("External controller tls listen error: %s", err)
		return nil
	}

	lc := inbound.NewListenConfig()
	lc.SetRouteMark(cfg.RoutingMark)
	rawListener, err := lc.Listen(context.Background(), "tcp", cfg.TLSAddr)
	if err != nil {
		log.Errorln("External controller tls listen error: %s", err)
		return nil
	}

	log.Infoln("RESTful API tls listening at: %s", rawListener.Addr().String())
	tlsConfig := &tls.Config{Time: ntp.Now}
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader()
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(cfg.ClientAuthType)
	if len(cfg.ClientAuthCert) > 0 && tlsConfig.ClientAuth == tls.NoClientCert {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, loadErr := ca.LoadCertificates(cfg.ClientAuthCert)
		if loadErr != nil {
			log.Errorln("External controller tls listen error: %s", loadErr)
			_ = rawListener.Close()
			return nil
		}
		tlsConfig.ClientCAs = pool
	}

	if cfg.EchKey != "" {
		if loadErr := ech.LoadECHKey(cfg.EchKey, tlsConfig); loadErr != nil {
			log.Errorln("External controller tls serve error: %s", loadErr)
			_ = rawListener.Close()
			return nil
		}
	}

	return &managedServer{
		generation: generation,
		logPrefix:  "External controller tls serve error",
		server: &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		},
		listener: tls.NewListener(rawListener, tlsConfig),
	}
}

func prepareUnixServer(cfg *Config, generation uint64) *managedServer {
	if len(cfg.UnixAddr) == 0 {
		return nil
	}
	addr := C.Path.Resolve(cfg.UnixAddr)

	dir := filepath.Dir(addr)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Errorln("External controller unix listen error: %s", err)
			return nil
		}
	}

	// https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
	//
	// Note: As mentioned above in the ‘security’ section, when a socket binds a socket to a valid pathname address,
	// a socket file is created within the filesystem. On Linux, the application is expected to unlink
	// (see the notes section in the man page for AF_UNIX) before any other socket can be bound to the same address.
	// The same applies to Windows unix sockets, except that, DeleteFile (or any other file delete API)
	// should be used to delete the socket file prior to calling bind with the same path.
	_ = syscall.Unlink(addr)

	lc := inbound.NewListenConfig()
	lc.SetRouteMark(0) // don't set route mark for unix socket
	listener, err := lc.Listen(context.Background(), "unix", addr)
	if err != nil {
		log.Errorln("External controller unix listen error: %s", err)
		return nil
	}
	_ = os.Chmod(addr, 0o666)
	log.Infoln("RESTful API unix listening at: %s", listener.Addr().String())

	return &managedServer{
		generation: generation,
		logPrefix:  "External controller unix serve error",
		server: &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		},
		listener: listener,
	}
}

func preparePipeServer(cfg *Config, generation uint64) *managedServer {
	if len(cfg.PipeAddr) == 0 {
		return nil
	}
	if !strings.HasPrefix(cfg.PipeAddr, "\\\\.\\pipe\\") { // windows namedpipe must start with "\\.\pipe\"
		log.Errorln("External controller pipe listen error: windows namedpipe must start with \"\\\\.\\pipe\\\"")
		return nil
	}

	listener, err := inbound.ListenNamedPipe(cfg.PipeAddr)
	if err != nil {
		log.Errorln("External controller pipe listen error: %s", err)
		return nil
	}
	log.Infoln("RESTful API pipe listening at: %s", listener.Addr().String())

	return &managedServer{
		generation: generation,
		logPrefix:  "External controller pipe serve error",
		server: &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		},
		listener: listener,
	}
}

func safeEqual(a, b string) bool {
	aBuf := utils.ImmutableBytesFromString(a)
	bBuf := utils.ImmutableBytesFromString(b)
	return subtle.ConstantTimeCompare(aBuf, bBuf) == 1
}

func authentication(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Browser websocket not support custom header
			if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != "" {
				token := r.URL.Query().Get("token")
				if !safeEqual(token, secret) {
					render.Status(r, http.StatusUnauthorized)
					render.JSON(w, r, ErrUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || !safeEqual(token, secret)
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"hello": "mihomo"})
}

func traffic(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	for range tick.C {
		buf.Reset()
		up, down := t.Now()
		upTotal, downTotal := t.Total()
		if err := json.NewEncoder(buf).Encode(Traffic{
			Up:        up,
			Down:      down,
			UpTotal:   upTotal,
			DownTotal: downTotal,
		}); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func memory(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	first := true
	for range tick.C {
		buf.Reset()

		inuse := t.Memory()
		// make chat.js begin with zero
		// this is shit var,but we need output 0 for first time
		if first {
			inuse = 0
			first = false
		}
		if err := json.NewEncoder(buf).Encode(Memory{
			Inuse:   inuse,
			OSLimit: 0,
		}); err != nil {
			break
		}
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
type LogStructuredField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type LogStructured struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []LogStructuredField `json:"fields"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	levelText := r.URL.Query().Get("level")
	if levelText == "" {
		levelText = "info"
	}

	formatText := r.URL.Query().Get("format")
	isStructured := false
	if formatText == "structured" {
		isStructured = true
	}

	level, ok := log.LogLevelMapping[levelText]
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	ch := make(chan log.Event, 1024)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	buf := &bytes.Buffer{}

	go func() {
		for logM := range sub {
			select {
			case ch <- logM:
			default:
			}
		}
		close(ch)
	}()

	for logM := range ch {
		if logM.LogLevel < level {
			continue
		}
		buf.Reset()

		if !isStructured {
			if err := json.NewEncoder(buf).Encode(Log{
				Type:    logM.Type(),
				Payload: logM.Payload,
			}); err != nil {
				break
			}
		} else {
			newLevel := logM.Type()
			if newLevel == "warning" {
				newLevel = "warn"
			}
			if err := json.NewEncoder(buf).Encode(LogStructured{
				Time:    time.Now().Format(time.TimeOnly),
				Level:   newLevel,
				Message: logM.Payload,
				Fields:  []LogStructuredField{},
			}); err != nil {
				break
			}
		}

		var err error
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"meta": C.Meta, "version": C.Version})
}
