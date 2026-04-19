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
//
// 3x-ui is a single-admin panel. SSO does not create, link, or back-fill users
// — a successful SSO authentication simply grants a session that acts AS the
// single admin. The admin's username/password stays as an emergency fallback.
//
// Access policy is trust-on-first-use: the first SSO identity to pass auth
// has its `sub` recorded in the panel database (via SettingService), and
// every later login must match that sub. The operator is expected to be the
// one who clicks "Sign in with SSO" first — or, even safer, to restrict the
// Pocket-ID OIDC Client to their own User Group so only they can ever reach
// the callback.
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	UsernameClaim string

	RequireEmailVerified bool
}

func boolEnv(name string, defaultVal bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return defaultVal
	}
	return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
}

// LoadOIDCConfig reads XUI_OIDC_* env vars. Returns nil when any of the four
// required fields (issuer, client id, secret, redirect URL) is unset.
func LoadOIDCConfig() *OIDCConfig {
	c := &OIDCConfig{
		Issuer:               strings.TrimSpace(os.Getenv("XUI_OIDC_ISSUER")),
		ClientID:             strings.TrimSpace(os.Getenv("XUI_OIDC_CLIENT_ID")),
		ClientSecret:         strings.TrimSpace(os.Getenv("XUI_OIDC_CLIENT_SECRET")),
		RedirectURL:          strings.TrimSpace(os.Getenv("XUI_OIDC_REDIRECT_URL")),
		UsernameClaim:        strings.TrimSpace(os.Getenv("XUI_OIDC_USERNAME_CLAIM")),
		RequireEmailVerified: boolEnv("XUI_OIDC_REQUIRE_EMAIL_VERIFIED", true),
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
	// permanently disable SSO. Subsequent login attempts retry discovery, but
	// a failed discovery is cached for a short TTL to prevent amplifying load
	// on the IdP when /oidc/login is hit in a tight loop.
	provMu        sync.Mutex
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauthCfg      *oauth2.Config
	lastDiscErr   error
	lastDiscErrAt time.Time
	discoNegTTL   time.Duration

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
	// Loud warning if the configured redirect URL is http:// on a non-local
	// host — every OIDC temp cookie will then be sent without Secure, so a
	// network attacker can read the state/nonce/PKCE values. This is almost
	// always a misconfiguration (intended deployment is behind TLS).
	if strings.HasPrefix(strings.ToLower(cfg.RedirectURL), "http://") {
		if !strings.Contains(cfg.RedirectURL, "://localhost") &&
			!strings.Contains(cfg.RedirectURL, "://127.0.0.1") &&
			!strings.Contains(cfg.RedirectURL, "://[::1]") {
			logger.Errorf("OIDC: XUI_OIDC_REDIRECT_URL is http:// on a non-local host (%q); "+
				"state/nonce/PKCE cookies will NOT have the Secure flag. "+
				"Deploy behind TLS and set the redirect URL to https://.", cfg.RedirectURL)
		}
	}
	c := &OIDCController{cfg: cfg, discoNegTTL: 30 * time.Second}
	g.GET("/oidc/login", c.login)
	g.GET("/oidc/callback", c.callback)
	logger.Infof("OIDC: enabled for issuer %q client %q", cfg.Issuer, cfg.ClientID)
	return c
}

// ensureProvider lazily runs OIDC discovery and caches the result. On failure,
// the error is cached for discoNegTTL so a crashed IdP cannot be amplified
// into a sustained stream of 10-second blocking discovery calls from any
// unauthenticated HTTP client hitting /oidc/login.
func (a *OIDCController) ensureProvider(ctx context.Context) error {
	a.provMu.Lock()
	defer a.provMu.Unlock()
	if a.provider != nil {
		return nil
	}
	if a.lastDiscErr != nil && time.Since(a.lastDiscErrAt) < a.discoNegTTL {
		return a.lastDiscErr
	}
	discCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discCtx, a.cfg.Issuer)
	if err != nil {
		a.lastDiscErr = err
		a.lastDiscErrAt = time.Now()
		return err
	}
	a.lastDiscErr = nil
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
	// OIDC `sub` is opaque and must be preserved byte-for-byte for DB lookups,
	// so we cannot truncate it. Cap length instead; a pathologically long
	// subject is either a misconfigured/compromised IdP or an attack to bloat
	// log files and the users table.
	const maxSubjectLen = 255
	if len(subject) > maxSubjectLen {
		a.fail(c, http.StatusBadGateway, "SSO id_token sub is too long", nil)
		return
	}
	// Extract configured claim for display/logging only. Not used as an auth
	// decision input — that's the allow-list's job.
	var displayName string
	if v, present := claims[a.cfg.UsernameClaim]; present {
		if s, ok := v.(string); ok && s != "" {
			displayName = sanitizeUsername(s)
		}
	}

	_, _ = claims["email"].(string) // present for logs only — no policy use
	emailVerified, _ := toBool(claims["email_verified"])

	// email_verified: honored only when the id_token actually carries an email
	// claim; otherwise nothing to gate against.
	if a.cfg.RequireEmailVerified {
		if _, ok := claims["email"].(string); ok && !emailVerified {
			a.fail(c, http.StatusForbidden, "SSO email is not verified by the provider", nil)
			return
		}
	}

	// Trust-on-first-use binding, using a compare-and-set on the Setting row
	// so two concurrent first-login callbacks cannot both walk away believing
	// they bound. Whoever's UPDATE ... WHERE value='' hits first wins; the
	// loser reads the winner's sub back and (if it's not theirs) gets rejected.
	//
	// The operator can clear the binding via `x-ui setting -resetSsoBinding`
	// to re-bind (e.g. when switching IdP accounts or if the IdP itself
	// reassigned the subject).
	boundSubject, err := a.settingService.BindOIDCSubjectIfEmpty(subject)
	if err != nil {
		a.fail(c, http.StatusInternalServerError, "SSO: unable to read or write binding state", err)
		return
	}
	if boundSubject != subject {
		logger.Warningf("OIDC: sub mismatch, expected=%s got=%s ip=%s", boundSubject, subject, getRemoteIp(c))
		a.fail(c, http.StatusForbidden, "SSO identity does not match the bound admin", nil)
		return
	}

	// 2FA block: if TOTP is enabled on the panel, SSO cannot prove the admin
	// also holds the secret, so we refuse.
	if twoFactorEnabled, err := a.settingService.GetTwoFactorEnable(); err == nil && twoFactorEnabled {
		a.fail(c, http.StatusForbidden,
			"SSO login disabled while panel 2FA is enabled; disable 2FA to use SSO", nil)
		return
	}

	// 3x-ui is a single-admin panel. Load THE admin row; SSO grants a session
	// that acts AS that admin, without creating or linking any separate user.
	user, err := a.userService.GetFirstUser()
	if err != nil {
		a.fail(c, http.StatusInternalServerError, "SSO: unable to load admin account", err)
		return
	}
	if displayName == "" {
		displayName = user.Username
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
	session.SetMaxAge(c, sessionMaxAge*60, a.isSecureRequest(c))
	session.SetLoginUser(c, user)
	if err := s.Save(); err != nil {
		logger.Warning("OIDC: unable to save session:", err)
	}

	logger.Infof("OIDC login ok: admin=%s idp=%s sub=%s ip=%s", user.Username, displayName, subject, getRemoteIp(c))
	a.tgbot.UserLoginNotify(displayName, "SSO", getRemoteIp(c), time.Now().Format("2006-01-02 15:04:05"), 1)

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
// Delegates to the shared requestIsSecure helper so password-login and OIDC
// paths agree on the per-request answer for the same panel deployment.
func (a *OIDCController) isSecureRequest(c *gin.Context) bool {
	return requestIsSecure(c)
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

// sanitizeUsername strips control characters and caps length so a malicious
// IdP claim cannot inject newlines/ANSI sequences into logs and Telegram
// messages (which get rendered with MarkdownV2 / arbitrary consumer parsers).
// Returns an empty string when nothing printable remains.
func sanitizeUsername(s string) string {
	const maxLen = 128
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < 0x20 || ch == 0x7f {
			continue // skip C0 and DEL
		}
		b = append(b, ch)
		if len(b) >= maxLen {
			break
		}
	}
	return strings.TrimSpace(string(b))
}

// toBool accepts boolean claims in both real-bool form and the string form
// ("true"/"false") that some IdPs (notably older Okta) emit. Returns (ok=true,
// v=parsed) on success, (false, false) if the shape wasn't a recognizable bool.
func toBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		if s == "true" {
			return true, true
		}
		if s == "false" {
			return false, true
		}
	}
	return false, false
}
