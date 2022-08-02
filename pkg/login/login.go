package login

import (
	"errors"
	"strings"
	"time"

	dbTypes "github.com/kzdv/api/pkg/database/types"
	"github.com/kzdv/sso/database/models"
	"github.com/kzdv/sso/pkg/pkce"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"gorm.io/gorm/clause"
)

type TokenRequest struct {
	GrantType    string   `form:"grant_type" json:"grant_type"`
	ClientID     string   `form:"client_id" json:"client_id"`
	ClientSecret string   `form:"client_secret" json:"client_secret"`
	RefreshToken string   `form:"refresh_token" json:"refresh_token"`
	Code         string   `form:"code" json:"code"`
	RedirectURI  string   `form:"redirect_uri" json:"redirect_uri"`
	CodeVerifier string   `form:"code_verifier" json:"code_verifier"`
	ResponseType string   `form:"response_type" json:"response_type"`
	Scope        []string `form:"scope" json:"scope"`
}

var (
	ErrInvalidRequest       = errors.New("invalid_request")
	ErrInvalidClient  error = errors.New("invalid_client")
	ErrInvalidGrant   error = errors.New("invalid_grant")
	ErrInvalidToken   error = errors.New("invalid_token")
	ErrTokenExpired   error = errors.New("token_expired")
)

func HandleGrantType(req TokenRequest) (*dbTypes.OAuthLogin, *dbTypes.User, error) {
	switch req.GrantType {
	case "authorization_code":
		return AuthorizationCode(req)
	case "refresh_token":
		return RefreshToken(req)
	default:
		return nil, nil, ErrInvalidGrant
	}
}

func AuthorizationCode(req TokenRequest) (*dbTypes.OAuthLogin, *dbTypes.User, error) {
	login := dbTypes.OAuthLogin{}
	if err := models.DB.Joins("Client").Where("code = ?", req.Code).First(&login).Error; err != nil {
		return nil, nil, ErrInvalidRequest
	}
	defer models.DB.Delete(&login)

	if req.ClientID != login.Client.ClientID || req.ClientSecret != login.Client.ClientSecret {
		return nil, nil, ErrInvalidClient
	}

	// Was the request PKCE'd?
	if login.CodeChallengeMethod == "S256" {
		if !pkce.VerifyCodeVerifierS256(login.CodeChallenge, req.CodeVerifier) {
			return nil, nil, ErrInvalidGrant
		}
	}

	user := dbTypes.User{}
	if err := models.DB.Preload(clause.Associations).Where(dbTypes.User{CID: login.CID}).First(&user).Error; err != nil {
		return nil, nil, ErrInvalidRequest
	}

	return &login, &user, nil
}

func RefreshToken(req TokenRequest) (*dbTypes.OAuthLogin, *dbTypes.User, error) {
	if req.RefreshToken == "" {
		return nil, nil, ErrInvalidRequest
	}

	login := dbTypes.OAuthLogin{}
	if err := models.DB.Joins("Client").Where(dbTypes.OAuthLogin{Token: req.RefreshToken}).First(&login).Error; err != nil {
		return nil, nil, ErrInvalidRequest
	}
	defer models.DB.Delete(&login)

	if req.ClientID != login.Client.ClientID || req.ClientSecret != login.Client.ClientSecret {
		return nil, nil, ErrInvalidClient
	}

	user := dbTypes.User{}
	if err := models.DB.Preload(clause.Associations).Where(dbTypes.User{CID: login.CID}).First(&user).Error; err != nil {
		return nil, nil, ErrInvalidRequest
	}

	req.Scope = strings.Split(login.Scope, " ")

	return &login, &user, nil
}

func CreateRefreshToken(login *dbTypes.OAuthLogin, user *dbTypes.User) (string, error) {
	code, err := gonanoid.New(48)
	if err != nil {
		return "", err
	}
	token := dbTypes.OAuthLogin{
		ClientID:  login.ClientID,
		CID:       user.CID,
		Token:     code,
		Scope:     login.Scope,
		UserAgent: login.UserAgent,
		IP:        login.IP,
		ExpiresAt: time.Now().Add(time.Second * 30 * 24 * 60 * 60),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := models.DB.Create(&token).Error; err != nil {
		return "", err
	}
	return code, nil
}

func CleanupAuthorization(req TokenRequest) (bool, error) {
	switch req.GrantType {
	case "authorization_code":
		if err := models.DB.Joins("Client").Where("code = ?", req.Code).Delete(&dbTypes.OAuthLogin{}).Error; err != nil {
			return false, ErrInvalidRequest
		}
		return true, nil
	case "refresh_token":
		if err := models.DB.Joins("Client").Where(dbTypes.OAuthLogin{Token: req.RefreshToken}).Delete(&dbTypes.OAuthLogin{}).Error; err != nil {
			return false, ErrInvalidRequest
		}
		return true, nil
	default:
		return false, ErrInvalidGrant
	}
}
