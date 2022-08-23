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
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	dbTypes "github.com/kzdv/api/pkg/database/types"
	"github.com/kzdv/sso/database/models"
	loginpkg "github.com/kzdv/sso/pkg/login"
	"github.com/kzdv/sso/pkg/tokens"
	"github.com/kzdv/sso/pkg/utils"
	"hawton.dev/log4g"
)

type TokenRequest struct {
	GrantType    string   `form:"grant_type"`
	ClientID     string   `form:"client_id"`
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
	RefreshToken        string `json:"refresh_token"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

func PostToken(c *gin.Context) {
	treq := loginpkg.TokenRequest{}
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
		log4g.Category("controllers/token").Warning(fmt.Sprintf("Code %s not found", treq.Code))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	defer models.DB.Delete(&login)

	if treq.ClientID == "" || treq.ClientSecret == "" {
		// Not in query string, let's grab from Authorization header
		auth := c.Request.Header.Get("Authorization")
		if auth == "" {
			log4g.Category("controllers/token").Error("Invalid client: no creds passed.")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}

		if fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", login.Client.ClientID, login.Client.ClientSecret)))) != auth {
			log4g.Category("controllers/token").Error("Invalid client: creds did not match.")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}

		authstring := strings.Replace(auth, "Basic ", "", 1)
		authbytes, err := base64.StdEncoding.DecodeString(authstring)
		if err != nil {
			log4g.Category("controllers/token").Error("Invalid client: base64 decode failed: %+v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}
		authslice := strings.SplitN(string(authbytes), ":", 2)
		treq.ClientID = authslice[0]
		treq.ClientSecret = authslice[1]
	} else if treq.ClientID != login.Client.ClientID || treq.ClientSecret != login.Client.ClientSecret {
		log4g.Category("controllers/token").Error(fmt.Sprintf("Invalid client: %s does not match %s", treq.ClientID, login.Client.ClientID))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if login.CodeChallengeMethod == "S256" {
		hash := sha256.Sum256([]byte(treq.CodeVerifier))
		if login.CodeChallenge != base64.RawURLEncoding.EncodeToString(hash[:]) {
			log4g.Category("controllers/token").Error("Code Challenge failed")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		} else {
			auth := strings.Split(c.GetHeader("Authorization"), " ")[1]
			authBytes, err := base64.URLEncoding.DecodeString(auth)
			if err != nil {
				log4g.Category("controllers/token").Error("Failed base64 decoding %s %s", c.GetHeader("Authorization"), err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
				return
			}
			authslice := strings.SplitN(string(authBytes), ":", 2)
			treq.ClientID = authslice[0]
			treq.ClientSecret = authslice[1]
		}
	}

	l, user, err := loginpkg.HandleGrantType(treq)
	if err != nil {
		log4g.Category("controllers/token").Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(treq.Scope) == 0 {
		treq.Scope = strings.Split(l.Scope, " ")
	}

	var roles []string
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	ret := TokenResponse{
		TokenType: "bearer",
		ExpiresIn: l.Client.TTL,
	}
	if l != nil {
		ret.CodeChallenge = l.CodeChallenge
		ret.CodeChallengeMethod = l.CodeChallengeMethod
	}

	accessToken, err := tokens.CreateToken(
		utils.Getenv("SSO_ISSUERKEY", "auth.denartcc.org"),
		l.Client.Name,
		fmt.Sprint(l.CID),
		l.Client.TTL,
		map[string]interface{}{
			"roles": roles,
		},
	)
	if err != nil {
		log4g.Category("controllers/token").Error("Error creating access token: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ret.AccessToken = string(accessToken)

	if contains(treq.Scope, "openid") {
		idtoken, err := tokens.CreateToken(
			utils.Getenv("SSO_ISSUERKEY", "auth.denartcc.org"),
			l.Client.Name,
			fmt.Sprint(l.CID),
			l.Client.TTL,
			map[string]interface{}{
				"name":        fmt.Sprintf("%s %s", user.FirstName, user.LastName),
				"given_name":  user.FirstName,
				"family_name": user.LastName,
				"email":       user.Email,
				"roles":       roles,
				"nonce":       l.Nonce,
			},
		)
		if err != nil {
			log4g.Category("controllers/token").Error("Error creating id token: %s", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ret.IdToken = string(idtoken)
	}
	ret.RefreshToken, err = loginpkg.CreateRefreshToken(l, user)

	_, err = loginpkg.CleanupAuthorization(treq)
	if err != nil {
		log4g.Category("controllers/token").Error("Error cleaning up authorization: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
