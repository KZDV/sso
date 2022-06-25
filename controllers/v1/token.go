/*
   ZAU Single Sign-On
   Copyright (C) 2021  Daniel A. Hawton <daniel@hawton.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package v1

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kzdv/sso/database/models"
	utils "github.com/kzdv/sso/pkg/utils"
	dbTypes "github.com/kzdv/types/database"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"gorm.io/gorm/clause"
	"hawton.dev/log4g"
)

type TokenRequest struct {
	GrantType    string   `form:"grant_type"`
	ClientId     string   `form:"client_id"`
	ClientSecret string   `form:"client_secret"`
	Code         string   `form:"code"`
	RedirectURI  string   `form:"redirect_uri"`
	CodeVerifier string   `form:"code_verifier"`
	ResponseType string   `form:"response_type"`
	Scope        []string `form:"scope"`
}

type TokenResponse struct {
	AccessToken         string `json:"access_token"`
	ExpiresIn           int    `json:"expires_in"`
	TokenType           string `json:"token_type"`
	IdToken             string `json:"id_token"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

func PostToken(c *gin.Context) {
	treq := TokenRequest{}
	if err := c.ShouldBind(&treq); err != nil {
		log4g.Category("controllers/token").Error("Invalid request, missing field(s)")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	if treq.GrantType != "authorization_code" {
		log4g.Category("controllers/token").Error("Grant type is not authorization code")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	login := dbTypes.OAuthLogin{}
	if err := models.DB.Joins("Client").Where("code = ?", treq.Code).First(&login).Error; err != nil {
		log4g.Category("controllers/token").Error(fmt.Sprintf("Code %s not found", treq.Code))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	defer models.DB.Delete(&login)

	if treq.ClientId == "" || treq.ClientSecret == "" {
		// Not in query string, let's grab from Authorization header
		auth := c.Request.Header.Get("Authorization")
		if auth == "" {
			log4g.Category("controllers/token").Error("Invalid client: no creds passed.")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}

		if fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", login.Client.ClientId, login.Client.ClientSecret)))) != auth {
			log4g.Category("controllers/token").Error("Invalid client: creds did not match.")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}
	}

	if treq.ClientId != login.Client.ClientId || treq.ClientSecret != login.Client.ClientSecret {
		log4g.Category("controllers/token").Error(fmt.Sprintf("Invalid client: %s does not match %s", treq.ClientId, login.Client.ClientId))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if login.CodeChallengeMethod == "S256" {
		hash := sha256.Sum256([]byte(treq.CodeVerifier))
		if login.CodeChallenge != base64.RawURLEncoding.EncodeToString(hash[:]) {
			log4g.Category("controllers/token").Error("Code Challenge failed")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}
	}

	user := dbTypes.User{}
	if err := models.DB.Preload(clause.Associations).Where(dbTypes.User{CID: login.CID}).Find(&user).Error; err != nil {
		log4g.Category("controllers/token").Error("User %s not found", login.CID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	keyset, err := jwk.Parse([]byte(os.Getenv("SSO_JWKS")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		log4g.Category("controller/token").Error("Could not parse JWKs: %s", err.Error())
		return
	}

	rand.Seed(time.Now().Unix())
	i := rand.Intn(keyset.Len())
	key, ok := keyset.Get(i)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		log4g.Category("controllers/token").Error("Could not find current key in JWKs")
		return
	}
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		log4g.Category("controllers/token").Error("Could not find current key in JWKs")
		return
	}

	var roles []string
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	token := jwt.New()
	token.Set(jwt.IssuerKey, utils.Getenv("SSO_ISSUERKEY", "auth.denartcc.org"))
	token.Set(jwt.AudienceKey, login.Client.Name)
	token.Set(jwt.SubjectKey, fmt.Sprint(login.CID))
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(login.Client.TTL)*time.Second).Unix())
	token.Set("roles", roles)
	signed, err := jwt.Sign(token, jwa.SignatureAlgorithm(key.Algorithm()), key)
	if err != nil {
		log4g.Category("controllers/token").Error("Failed to create JWT: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid_grant"})
		return
	}

	ret := TokenResponse{
		AccessToken:         string(signed),
		ExpiresIn:           int(time.Hour*24*7) / int(time.Second),
		TokenType:           "Bearer",
		CodeChallenge:       login.CodeChallenge,
		CodeChallengeMethod: login.CodeChallengeMethod,
	}

	if contains(treq.Scope, "openid") && treq.ResponseType == "id_token" {
		token := jwt.New()
		token.Set(jwt.IssuerKey, utils.Getenv("SSO_ISSUERKEY", "auth.denartcc.org"))
		token.Set(jwt.AudienceKey, login.Client.Name)
		token.Set(jwt.SubjectKey, fmt.Sprint(login.CID))
		token.Set(jwt.IssuedAtKey, time.Now())
		token.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(login.Client.TTL)*time.Second).Unix())
		token.Set("name", fmt.Sprintf("%s %s", user.FirstName, user.LastName))
		token.Set("given_name", user.FirstName)
		token.Set("family_name", user.LastName)
		token.Set("roles", roles)
		idsigned, err := jwt.Sign(token, jwa.SignatureAlgorithm(key.Algorithm()), key)
		if err != nil {
			log4g.Category("controllers/token").Error("Failed to create JWT: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid_grant"})
			return
		}
		ret.IdToken = string(idsigned)
	}

	c.JSON(http.StatusOK, ret)
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
