package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const (
	oidcCookieState = "xui_oidc_state"
	oidcCookieNonce = "xui_oidc_nonce"
	oidcCookiePKCE  = "xui_oidc_pkce"
	oidcCookieTTL   = 600 // seconds
)

// OIDCConfig is the runtime OIDC configuration assembled from env vars.
// Empty instance with Enabled=false when not configured.
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	UsernameClaim string
	AutoCreate    bool
}

// LoadOIDCConfig reads XUI_OIDC_* env vars. Returns nil when the four required
// fields (issuer, client id, secret, redirect) are not all set.
func LoadOIDCConfig() *OIDCConfig {
	c := &OIDCConfig{
		Issuer:        strings.TrimSpace(os.Getenv("XUI_OIDC_ISSUER")),
		ClientID:      strings.TrimSpace(os.Getenv("XUI_OIDC_CLIENT_ID")),
		ClientSecret:  strings.TrimSpace(os.Getenv("XUI_OIDC_CLIENT_SECRET")),
		RedirectURL:   strings.TrimSpace(os.Getenv("XUI_OIDC_REDIRECT_URL")),
		UsernameClaim: strings.TrimSpace(os.Getenv("XUI_OIDC_USERNAME_CLAIM")),
		AutoCreate:    strings.EqualFold(os.Getenv("XUI_OIDC_AUTO_CREATE"), "true"),
	}
	if c.Issuer == "" || c.ClientID == "" || c.ClientSecret == "" || c.RedirectURL == "" {
		return nil
	}
	if c.UsernameClaim == "" {
		c.UsernameClaim = "email"
	}
	return c
}

// OIDCEnabled reports whether OIDC env vars are present; cheap helper for templates.
func OIDCEnabled() bool {
	return LoadOIDCConfig() != nil
}

// OIDCController handles the /oidc/login and /oidc/callback endpoints.
type OIDCController struct {
	BaseController

	cfg            *OIDCConfig
	provider       *oidc.Provider
	verifier       *oidc.IDTokenVerifier
	oauthCfg       *oauth2.Config
	userService    service.UserService
	settingService service.SettingService
	tgbot          service.Tgbot
}

// NewOIDCController wires OIDC routes onto the group. Returns nil (no routes
// registered) when OIDC env vars are absent or provider discovery fails — the
// caller must tolerate a nil return and treat it as "OIDC disabled".
func NewOIDCController(g *gin.RouterGroup) *OIDCController {
	cfg := LoadOIDCConfig()
	if cfg == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		logger.Warningf("OIDC: discovery failed for %q: %v", cfg.Issuer, err)
		return nil
	}
	c := &OIDCController{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauthCfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
	}
	g.GET("/oidc/login", c.login)
	g.GET("/oidc/callback", c.callback)
	logger.Infof("OIDC: enabled for issuer %q client %q", cfg.Issuer, cfg.ClientID)
	return c
}

func (a *OIDCController) login(c *gin.Context) {
	if session.IsLogin(c) {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"panel/")
		return
	}
	state, err := randString(32)
	if err != nil {
		a.fail(c, http.StatusInternalServerError, err)
		return
	}
	nonce, err := randString(32)
	if err != nil {
		a.fail(c, http.StatusInternalServerError, err)
		return
	}
	pkce := oauth2.GenerateVerifier()

	setTempCookie(c, oidcCookieState, state)
	setTempCookie(c, oidcCookieNonce, nonce)
	setTempCookie(c, oidcCookiePKCE, pkce)

	url := a.oauthCfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkce),
	)
	c.Redirect(http.StatusFound, url)
}

func (a *OIDCController) callback(c *gin.Context) {
	expectedState, _ := c.Cookie(oidcCookieState)
	expectedNonce, _ := c.Cookie(oidcCookieNonce)
	pkce, _ := c.Cookie(oidcCookiePKCE)
	clearTempCookie(c, oidcCookieState)
	clearTempCookie(c, oidcCookieNonce)
	clearTempCookie(c, oidcCookiePKCE)

	if errParam := c.Query("error"); errParam != "" {
		desc := c.Query("error_description")
		a.fail(c, http.StatusBadRequest, fmt.Errorf("idp error: %s: %s", errParam, desc))
		return
	}
	if expectedState == "" || c.Query("state") != expectedState {
		a.fail(c, http.StatusBadRequest, errors.New("invalid state"))
		return
	}
	code := c.Query("code")
	if code == "" {
		a.fail(c, http.StatusBadRequest, errors.New("missing code"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	token, err := a.oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(pkce))
	if err != nil {
		a.fail(c, http.StatusBadGateway, fmt.Errorf("token exchange: %w", err))
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		a.fail(c, http.StatusBadGateway, errors.New("no id_token in response"))
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		a.fail(c, http.StatusBadGateway, fmt.Errorf("verify id_token: %w", err))
		return
	}
	if idToken.Nonce != expectedNonce {
		a.fail(c, http.StatusBadRequest, errors.New("invalid nonce"))
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		a.fail(c, http.StatusBadGateway, fmt.Errorf("parse claims: %w", err))
		return
	}
	subject := idToken.Subject
	if subject == "" {
		a.fail(c, http.StatusBadGateway, errors.New("id_token has empty sub claim"))
		return
	}
	fallbackUsername, _ := claims[a.cfg.UsernameClaim].(string)

	user, err := a.userService.GetOrLinkOIDCUser(subject, fallbackUsername, a.cfg.AutoCreate)
	if err != nil {
		logger.Warningf("OIDC login rejected sub=%q name=%q: %v", subject, fallbackUsername, err)
		a.tgbot.UserLoginNotify(fallbackUsername, "SSO:unbound", getRemoteIp(c), time.Now().Format("2006-01-02 15:04:05"), 0)
		a.fail(c, http.StatusForbidden, errors.New("SSO identity is not bound to any panel account"))
		return
	}

	sessionMaxAge, err := a.settingService.GetSessionMaxAge()
	if err != nil {
		logger.Warning("OIDC: unable to get session max age:", err)
	}
	session.SetMaxAge(c, sessionMaxAge*60)
	session.SetLoginUser(c, user)
	if err := sessions.Default(c).Save(); err != nil {
		logger.Warning("OIDC: unable to save session:", err)
	}

	logger.Infof("OIDC login ok: user=%s sub=%s ip=%s", user.Username, subject, getRemoteIp(c))
	a.tgbot.UserLoginNotify(user.Username, "SSO", getRemoteIp(c), time.Now().Format("2006-01-02 15:04:05"), 1)

	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"panel/")
}

func (a *OIDCController) fail(c *gin.Context, status int, err error) {
	logger.Warning("OIDC: ", err)
	c.String(status, "SSO login failed: %v\n", err)
}

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setTempCookie(c *gin.Context, name, value string) {
	c.SetCookie(name, value, oidcCookieTTL, "/", "", isSecureRequest(c), true)
}

func clearTempCookie(c *gin.Context, name string) {
	c.SetCookie(name, "", -1, "/", "", isSecureRequest(c), true)
}

func isSecureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	if proto := c.GetHeader("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}
