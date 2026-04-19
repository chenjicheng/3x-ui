package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
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
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	UsernameClaim string

	RequireEmailVerified  bool
	AllowUsernameBackfill bool
	AutoCreate            bool
	AllowedSubjects       map[string]struct{}
	AllowedEmails         map[string]struct{}
}

func boolEnv(name string, defaultVal bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return defaultVal
	}
	return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
}

func setEnv(name string) map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	out := make(map[string]struct{})
	for _, p := range strings.Split(raw, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

// LoadOIDCConfig reads XUI_OIDC_* env vars. Returns nil when the four required
// fields (issuer, client id, secret, redirect) are not all set.
func LoadOIDCConfig() *OIDCConfig {
	c := &OIDCConfig{
		Issuer:                strings.TrimSpace(os.Getenv("XUI_OIDC_ISSUER")),
		ClientID:              strings.TrimSpace(os.Getenv("XUI_OIDC_CLIENT_ID")),
		ClientSecret:          strings.TrimSpace(os.Getenv("XUI_OIDC_CLIENT_SECRET")),
		RedirectURL:           strings.TrimSpace(os.Getenv("XUI_OIDC_REDIRECT_URL")),
		UsernameClaim:         strings.TrimSpace(os.Getenv("XUI_OIDC_USERNAME_CLAIM")),
		RequireEmailVerified:  boolEnv("XUI_OIDC_REQUIRE_EMAIL_VERIFIED", true),
		AllowUsernameBackfill: boolEnv("XUI_OIDC_ALLOW_USERNAME_BACKFILL", false),
		AutoCreate:            boolEnv("XUI_OIDC_AUTO_CREATE", false),
		AllowedSubjects:       setEnv("XUI_OIDC_ALLOWED_SUBJECTS"),
		AllowedEmails:         setEnv("XUI_OIDC_ALLOWED_EMAILS"),
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

// OIDCController handles /oidc/login and /oidc/callback.
type OIDCController struct {
	BaseController

	cfg *OIDCConfig

	// provider is initialized lazily — a transient IdP outage at boot must not
	// permanently disable SSO. Subsequent login attempts retry discovery.
	provMu   sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauthCfg *oauth2.Config

	userService    service.UserService
	settingService service.SettingService
	tgbot          service.Tgbot
}

// NewOIDCController wires OIDC routes onto the group. Returns nil when OIDC
// env vars are absent. Provider discovery happens on the first login attempt
// so the panel still starts when the IdP is transiently unreachable.
func NewOIDCController(g *gin.RouterGroup) *OIDCController {
	cfg := LoadOIDCConfig()
	if cfg == nil {
		return nil
	}
	c := &OIDCController{cfg: cfg}
	g.GET("/oidc/login", c.login)
	g.GET("/oidc/callback", c.callback)
	logger.Infof("OIDC: enabled for issuer %q client %q", cfg.Issuer, cfg.ClientID)
	return c
}

// ensureProvider lazily runs OIDC discovery and caches the result.
func (a *OIDCController) ensureProvider(ctx context.Context) error {
	a.provMu.Lock()
	defer a.provMu.Unlock()
	if a.provider != nil {
		return nil
	}
	discCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discCtx, a.cfg.Issuer)
	if err != nil {
		return err
	}
	a.provider = provider
	a.verifier = provider.Verifier(&oidc.Config{
		ClientID:             a.cfg.ClientID,
		SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"},
	})
	a.oauthCfg = &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		RedirectURL:  a.cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return nil
}

func (a *OIDCController) login(c *gin.Context) {
	if session.IsLogin(c) {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"panel/")
		return
	}
	if err := a.ensureProvider(c.Request.Context()); err != nil {
		a.fail(c, http.StatusServiceUnavailable, "SSO provider is currently unavailable", err)
		return
	}
	state, err := randString(32)
	if err != nil {
		a.fail(c, http.StatusInternalServerError, "internal error", err)
		return
	}
	nonce, err := randString(32)
	if err != nil {
		a.fail(c, http.StatusInternalServerError, "internal error", err)
		return
	}
	pkce := oauth2.GenerateVerifier()

	secure := a.isSecureRequest(c)
	setTempCookie(c, oidcCookieState, state, secure)
	setTempCookie(c, oidcCookieNonce, nonce, secure)
	setTempCookie(c, oidcCookiePKCE, pkce, secure)

	url := a.oauthCfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkce),
	)
	c.Redirect(http.StatusFound, url)
}

func (a *OIDCController) callback(c *gin.Context) {
	secure := a.isSecureRequest(c)

	expectedState, _ := c.Cookie(oidcCookieState)
	expectedNonce, _ := c.Cookie(oidcCookieNonce)
	pkce, _ := c.Cookie(oidcCookiePKCE)
	clearTempCookie(c, oidcCookieState, secure)
	clearTempCookie(c, oidcCookieNonce, secure)
	clearTempCookie(c, oidcCookiePKCE, secure)

	if errParam := c.Query("error"); errParam != "" {
		a.fail(c, http.StatusBadRequest, "SSO provider returned an error",
			errors.New("idp error: "+errParam+" desc="+c.Query("error_description")))
		return
	}
	if expectedState == "" || c.Query("state") != expectedState {
		a.fail(c, http.StatusBadRequest, "invalid or expired SSO state", errors.New("state mismatch"))
		return
	}
	code := c.Query("code")
	if code == "" {
		a.fail(c, http.StatusBadRequest, "missing code", nil)
		return
	}

	if err := a.ensureProvider(c.Request.Context()); err != nil {
		a.fail(c, http.StatusServiceUnavailable, "SSO provider is currently unavailable", err)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	token, err := a.oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(pkce))
	if err != nil {
		a.fail(c, http.StatusBadGateway, "SSO token exchange failed", err)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		a.fail(c, http.StatusBadGateway, "SSO token response missing id_token", nil)
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		a.fail(c, http.StatusBadGateway, "SSO id_token verification failed", err)
		return
	}
	if idToken.Nonce != expectedNonce {
		a.fail(c, http.StatusBadRequest, "SSO nonce mismatch", nil)
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		a.fail(c, http.StatusBadGateway, "SSO claims parse failed", err)
		return
	}
	subject := idToken.Subject
	if subject == "" {
		a.fail(c, http.StatusBadGateway, "SSO id_token has empty sub", nil)
		return
	}
	// Strictly extract the configured username claim.
	var fallbackUsername string
	if v, present := claims[a.cfg.UsernameClaim]; present {
		s, isStr := v.(string)
		if !isStr || s == "" {
			a.fail(c, http.StatusBadGateway, "SSO claim is not a non-empty string",
				errors.New("claim "+a.cfg.UsernameClaim+" had unsupported type or was empty"))
			return
		}
		fallbackUsername = s
	}

	// email_verified: when the configured username claim is derived from an email,
	// refuse unverified emails. Default on.
	if a.cfg.RequireEmailVerified && claimsIndicateEmail(a.cfg.UsernameClaim) {
		verified, _ := claims["email_verified"].(bool)
		if !verified {
			a.fail(c, http.StatusForbidden, "SSO email is not verified by the provider", nil)
			return
		}
	}

	// Allow-list check: when configured, the subject OR the email (whichever is
	// configured) must match one of the allowed values. Prevents open IdPs from
	// auto-provisioning random users.
	if len(a.cfg.AllowedSubjects) > 0 {
		if _, ok := a.cfg.AllowedSubjects[strings.ToLower(subject)]; !ok {
			a.fail(c, http.StatusForbidden, "SSO identity is not permitted", nil)
			return
		}
	}
	if len(a.cfg.AllowedEmails) > 0 {
		emailClaim, _ := claims["email"].(string)
		if emailClaim == "" {
			a.fail(c, http.StatusForbidden, "SSO email is not permitted", nil)
			return
		}
		if _, ok := a.cfg.AllowedEmails[strings.ToLower(emailClaim)]; !ok {
			a.fail(c, http.StatusForbidden, "SSO email is not permitted", nil)
			return
		}
	}

	policy := service.OIDCLinkPolicy{
		AllowUsernameBackfill: a.cfg.AllowUsernameBackfill,
		AutoCreate:            a.cfg.AutoCreate,
	}
	user, err := a.userService.GetOrLinkOIDCUser(subject, fallbackUsername, policy)
	if err != nil {
		logger.Warningf("OIDC login rejected sub=%q name=%q: %v", subject, fallbackUsername, err)
		a.tgbot.UserLoginNotify(fallbackUsername, "SSO:unbound", getRemoteIp(c), time.Now().Format("2006-01-02 15:04:05"), 0)
		a.fail(c, http.StatusForbidden, "SSO identity is not bound to any panel account", nil)
		return
	}

	// If 2FA is enabled on this panel, SSO alone is not sufficient; the IdP
	// cannot attest that the admin also holds the panel's TOTP secret. Reject
	// to avoid creating a backdoor around 2FA. Operators who want SSO-without-
	// 2FA must disable 2FA in panel settings explicitly.
	if twoFactorEnabled, err := a.settingService.GetTwoFactorEnable(); err == nil && twoFactorEnabled {
		a.fail(c, http.StatusForbidden,
			"SSO login disabled while panel 2FA is enabled; disable 2FA to use SSO", nil)
		return
	}

	// Rotate the session before attaching the logged-in user to avoid session
	// fixation: any values a pre-auth attacker may have placed in the cookie
	// are wiped here.
	s := sessions.Default(c)
	s.Clear()

	sessionMaxAge, err := a.settingService.GetSessionMaxAge()
	if err != nil || sessionMaxAge <= 0 {
		if err != nil {
			logger.Warning("OIDC: unable to get session max age, using default:", err)
		}
		sessionMaxAge = 60 // minutes
	}
	session.SetMaxAge(c, sessionMaxAge*60)
	session.SetLoginUser(c, user)
	if err := s.Save(); err != nil {
		logger.Warning("OIDC: unable to save session:", err)
	}

	logger.Infof("OIDC login ok: user=%s sub=%s ip=%s", user.Username, subject, getRemoteIp(c))
	a.tgbot.UserLoginNotify(user.Username, "SSO", getRemoteIp(c), time.Now().Format("2006-01-02 15:04:05"), 1)

	c.Redirect(http.StatusFound, c.GetString("base_path")+"panel/")
}

// fail logs detail server-side but returns only a generic, caller-provided
// message to the browser to avoid reflecting upstream errors / attacker-
// controlled error_description content.
func (a *OIDCController) fail(c *gin.Context, status int, publicMsg string, detail error) {
	if detail != nil {
		logger.Warningf("OIDC: %s: %v", publicMsg, detail)
	} else {
		logger.Warningf("OIDC: %s", publicMsg)
	}
	c.String(status, "SSO login failed: %s\n", publicMsg)
}

// isSecureRequest decides whether to set the Secure flag on OIDC temp cookies.
// Honors X-Forwarded-Proto only if XUI_OIDC_TRUST_FORWARDED_PROTO=true, so an
// untrusted client can't flip the Secure flag by spoofing a header.
func (a *OIDCController) isSecureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	if boolEnv("XUI_OIDC_TRUST_FORWARDED_PROTO", false) {
		return strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
	}
	// Panel deployed behind a reverse proxy where the callback URL is https —
	// infer from the configured redirect URL's scheme rather than sniffing
	// client-supplied headers.
	return strings.HasPrefix(strings.ToLower(a.cfg.RedirectURL), "https://")
}

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setTempCookie(c *gin.Context, name, value string, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   oidcCookieTTL,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearTempCookie(c *gin.Context, name string, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func claimsIndicateEmail(claim string) bool {
	c := strings.ToLower(claim)
	return c == "email" || strings.HasSuffix(c, "_email") || c == "mail"
}
