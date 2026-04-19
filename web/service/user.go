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

// GetOrLinkOIDCUser resolves the local user bound to the given OIDC subject.
//
// The lookup is in three steps:
//  1. Match an existing user whose oidc_subject equals `subject` (stable across IdP email changes).
//  2. Fall back to matching an existing user whose username equals `fallbackUsername` AND whose
//     oidc_subject is empty. This is the one-time migration for admins who signed up with
//     password auth before SSO was enabled; the subject is backfilled on that row.
//  3. If autoCreate is true and no match is found, a new user is created with Username =
//     fallbackUsername, OIDCSubject = subject, and a random password (effectively SSO-only).
//
// Returns an error when no match is found and autoCreate is false, or when the fallback
// username exists but is already bound to a different OIDC subject (prevents takeover).
func (s *UserService) GetOrLinkOIDCUser(subject string, fallbackUsername string, autoCreate bool) (*model.User, error) {
	if subject == "" {
		return nil, errors.New("empty oidc subject")
	}
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(&model.User{}).Where("oidc_subject = ?", subject).First(user).Error
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Warning("oidc user lookup by subject err:", err)
		return nil, err
	}

	if fallbackUsername != "" {
		byName := &model.User{}
		err = db.Model(&model.User{}).Where("username = ?", fallbackUsername).First(byName).Error
		if err == nil {
			if byName.OIDCSubject != "" && byName.OIDCSubject != subject {
				return nil, errors.New("username already bound to a different SSO identity")
			}
			byName.OIDCSubject = subject
			if err := db.Save(byName).Error; err != nil {
				logger.Warning("oidc subject backfill err:", err)
				return nil, err
			}
			return byName, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warning("oidc user lookup by username err:", err)
			return nil, err
		}
	}

	if !autoCreate {
		return nil, errors.New("no local account bound to this SSO identity")
	}

	pwBytes := make([]byte, 24)
	if _, rerr := rand.Read(pwBytes); rerr != nil {
		return nil, rerr
	}
	randomPassword := base64.RawURLEncoding.EncodeToString(pwBytes)
	hashed, herr := crypto.HashPasswordAsBcrypt(randomPassword)
	if herr != nil {
		return nil, herr
	}
	newUser := &model.User{
		Username:    fallbackUsername,
		Password:    hashed,
		OIDCSubject: subject,
	}
	if newUser.Username == "" {
		newUser.Username = "sso-" + subject
	}
	if err := db.Create(newUser).Error; err != nil {
		return nil, err
	}
	return newUser, nil
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
