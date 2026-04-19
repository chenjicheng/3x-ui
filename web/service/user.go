package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	ldaputil "github.com/mhsanaei/3x-ui/v2/util/ldap"
	"github.com/xlzd/gotp"
	"gorm.io/gorm"
)

// UserService provides business logic for user management and authentication.
// It handles user creation, login, password management, and 2FA operations.
type UserService struct {
	settingService SettingService
}

// GetFirstUser retrieves the first user from the database.
// This is typically used for initial setup or when there's only one admin user.
func (s *UserService) GetFirstUser() (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(model.User{}).
		First(user).
		Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) CheckUser(username string, password string, twoFactorCode string) (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}

	err := db.Model(model.User{}).
		Where("username = ?", username).
		First(user).
		Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.New("invalid credentials")
	} else if err != nil {
		logger.Warning("check user err:", err)
		return nil, err
	}

	if !crypto.CheckPasswordHash(user.Password, password) {
		ldapEnabled, _ := s.settingService.GetLdapEnable()
		if !ldapEnabled {
			return nil, errors.New("invalid credentials")
		}

		host, _ := s.settingService.GetLdapHost()
		port, _ := s.settingService.GetLdapPort()
		useTLS, _ := s.settingService.GetLdapUseTLS()
		bindDN, _ := s.settingService.GetLdapBindDN()
		ldapPass, _ := s.settingService.GetLdapPassword()
		baseDN, _ := s.settingService.GetLdapBaseDN()
		userFilter, _ := s.settingService.GetLdapUserFilter()
		userAttr, _ := s.settingService.GetLdapUserAttr()

		cfg := ldaputil.Config{
			Host:       host,
			Port:       port,
			UseTLS:     useTLS,
			BindDN:     bindDN,
			Password:   ldapPass,
			BaseDN:     baseDN,
			UserFilter: userFilter,
			UserAttr:   userAttr,
		}
		ok, err := ldaputil.AuthenticateUser(cfg, username, password)
		if err != nil || !ok {
			return nil, errors.New("invalid credentials")
		}
	}

	twoFactorEnable, err := s.settingService.GetTwoFactorEnable()
	if err != nil {
		logger.Warning("check two factor err:", err)
		return nil, err
	}

	if twoFactorEnable {
		twoFactorToken, err := s.settingService.GetTwoFactorToken()

		if err != nil {
			logger.Warning("check two factor token err:", err)
			return nil, err
		}

		if gotp.NewDefaultTOTP(twoFactorToken).Now() != twoFactorCode {
			return nil, errors.New("invalid 2fa code")
		}
	}

	return user, nil
}

func (s *UserService) UpdateUser(id int, username string, password string) error {
	db := database.GetDB()
	hashedPassword, err := crypto.HashPasswordAsBcrypt(password)

	if err != nil {
		return err
	}

	twoFactorEnable, err := s.settingService.GetTwoFactorEnable()
	if err != nil {
		return err
	}

	if twoFactorEnable {
		s.settingService.SetTwoFactorEnable(false)
		s.settingService.SetTwoFactorToken("")
	}

	return db.Model(model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{"username": username, "password": hashedPassword}).
		Error
}

// OIDCLinkPolicy configures how GetOrLinkOIDCUser resolves the local user for
// an IdP-authenticated identity. Default (zero value) is the safe option:
// only match a user whose oidc_subject already equals `subject`. Any first-time
// binding must be explicitly opted into with AllowUsernameBackfill or AutoCreate.
type OIDCLinkPolicy struct {
	// AllowUsernameBackfill lets an IdP-authenticated call link an existing
	// password-only user row whose `username` equals the supplied fallback.
	// Off by default to prevent takeover when the IdP is not a trust boundary.
	AllowUsernameBackfill bool

	// AutoCreate lets an IdP-authenticated call create a brand new panel user
	// when no binding exists. 3x-ui has no role system — a created user is a
	// full admin. Off by default. When on, the caller SHOULD restrict access
	// to the IdP side (e.g. Pocket-ID user group restrictions).
	AutoCreate bool
}

// GetOrLinkOIDCUser resolves the local user bound to the given OIDC subject.
//
// Resolution order, all inside a single DB transaction to avoid a concurrent
// callback racing itself to a duplicate row:
//  1. Match by oidc_subject = subject (the stable binding, unaffected by IdP
//     email/username changes).
//  2. If policy.AllowUsernameBackfill, match by username = fallbackUsername
//     where the existing row has NULL oidc_subject; backfill the subject.
//  3. If policy.AutoCreate, create a new user with a random password and the
//     subject attached.
//
// Returns an error when nothing matches and no policy permits creation/link,
// or when the fallback username is already bound to a *different* subject.
func (s *UserService) GetOrLinkOIDCUser(subject string, fallbackUsername string, policy OIDCLinkPolicy) (*model.User, error) {
	if subject == "" {
		return nil, errors.New("empty oidc subject")
	}
	db := database.GetDB()

	var result *model.User
	err := db.Transaction(func(tx *gorm.DB) error {
		bySub := &model.User{}
		err := tx.Model(&model.User{}).Where("oidc_subject = ?", subject).First(bySub).Error
		if err == nil {
			result = bySub
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warning("oidc user lookup by subject err:", err)
			return err
		}

		if policy.AllowUsernameBackfill && fallbackUsername != "" {
			byName := &model.User{}
			err = tx.Model(&model.User{}).Where("username = ?", fallbackUsername).First(byName).Error
			if err == nil {
				if byName.OIDCSubject != nil && *byName.OIDCSubject != "" && *byName.OIDCSubject != subject {
					return errors.New("username already bound to a different SSO identity")
				}
				sub := subject
				byName.OIDCSubject = &sub
				if err := tx.Save(byName).Error; err != nil {
					logger.Warning("oidc subject backfill err:", err)
					return err
				}
				result = byName
				return nil
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				logger.Warning("oidc user lookup by username err:", err)
				return err
			}
		}

		if !policy.AutoCreate {
			return errors.New("no local account bound to this SSO identity")
		}

		pwBytes := make([]byte, 24)
		if _, rerr := rand.Read(pwBytes); rerr != nil {
			return rerr
		}
		randomPassword := base64.RawURLEncoding.EncodeToString(pwBytes)
		hashed, herr := crypto.HashPasswordAsBcrypt(randomPassword)
		if herr != nil {
			return herr
		}
		sub := subject
		newUser := &model.User{
			Username:    fallbackUsername,
			Password:    hashed,
			OIDCSubject: &sub,
		}
		if newUser.Username == "" {
			newUser.Username = "sso-" + subject
		}
		if err := tx.Create(newUser).Error; err != nil {
			return err
		}
		result = newUser
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *UserService) UpdateFirstUser(username string, password string) error {
	if username == "" {
		return errors.New("username can not be empty")
	} else if password == "" {
		return errors.New("password can not be empty")
	}
	hashedPassword, er := crypto.HashPasswordAsBcrypt(password)

	if er != nil {
		return er
	}

	db := database.GetDB()
	user := &model.User{}
	err := db.Model(model.User{}).First(user).Error
	if database.IsNotFound(err) {
		user.Username = username
		user.Password = hashedPassword
		return db.Model(model.User{}).Create(user).Error
	} else if err != nil {
		return err
	}
	user.Username = username
	user.Password = hashedPassword
	return db.Save(user).Error
}
