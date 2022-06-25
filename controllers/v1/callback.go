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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kzdv/sso/database/models"
	dbTypes "github.com/kzdv/types/database"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"hawton.dev/log4g"
)

type Result struct {
	cid int
	err error
}

type UserResponse struct {
	CID      int                  `json:"cid"`
	Personal UserResponsePersonal `json:"personal"`
}

type UserResponsePersonal struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	FullName  string `json:"full_name"`
}

type VatsimAccessToken struct {
	AccessToken string `json:"access_token"`
}

type VatsimResponse struct {
	Data UserResponse `json:"data"`
}

func GetCallback(c *gin.Context) {
	code, exists := c.GetQuery("code")
	if !exists {
		handleError(c, "Invalid response received from Authenticator or Authentication cancelled.")
		return
	}

	cstate, err := c.Cookie("sso_token")
	if err != nil {
		handleError(c, "Invalid response received from Authenticator or Authentication cancelled.")
		return
	}

	login := dbTypes.OAuthLogin{}
	if err = models.DB.Where("token = ? AND created_at < ?", cstate, time.Now().Add(time.Minute*5)).First(&login).Error; err != nil {
		log4g.Category("controllers/callback").Error("Token used that isn't in db, duplicate request? " + cstate)
		handleError(c, "Token is invalid.")
		return
	}

	if login.UserAgent != c.Request.UserAgent() {
		handleError(c, "Token is not valid.")
		go models.DB.Delete(login)
		return
	}

	scheme := "https"
	returnUri := url.QueryEscape(fmt.Sprintf("%s://%s/oauth/callback", scheme, c.Request.Host))

	result := make(chan Result)
	go func() {
		tokenUrl := fmt.Sprintf("%s%s", os.Getenv("VATSIM_BASE_URL"), os.Getenv("VATSIM_TOKEN_PATH"))

		data := url.Values{}
		data.Set("grant_type", "authorization_code")
		data.Set("code", code)
		data.Set("redirect_uri", returnUri)
		data.Set("client_id", os.Getenv("VATSIM_OAUTH_CLIENT_ID"))
		data.Set("client_secret", os.Getenv("VATSIM_OAUTH_CLIENT_SECRET"))

		json_data, err := json.Marshal(data)
		if err != nil {
			result <- Result{err: err}
			return
		}

		request, err := http.Post(tokenUrl, "application/json", bytes.NewBuffer(json_data))
		if err != nil {
			result <- Result{err: err}
			return
		}
		defer request.Body.Close()
		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			result <- Result{err: err}
			return
		}
		accessToken := &VatsimAccessToken{}
		if err = json.Unmarshal(body, accessToken); err != nil {
			result <- Result{err: err}
			return
		}

		if accessToken.AccessToken == "" {
			result <- Result{err: fmt.Errorf("No access token received")}
			return
		}

		userRequest, err := http.NewRequest("GET", fmt.Sprintf("%s%s", os.Getenv("VATSIM_BASE_URL"), os.Getenv("VATSIM_USER_PATH")), nil)
		userRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken.AccessToken))
		if err != nil {
			result <- Result{err: err}
			return
		}

		userResponse, err := http.DefaultClient.Do(userRequest)
		if err != nil {
			result <- Result{err: err}
			return
		}
		defer userResponse.Body.Close()
		userBody, err := ioutil.ReadAll(userResponse.Body)
		if err != nil {
			result <- Result{err: err}
			return
		}

		vatsimResponse := &VatsimResponse{}
		if err = json.Unmarshal(userBody, vatsimResponse); err != nil {
			result <- Result{err: err}
			return
		}

		result <- Result{cid: vatsimResponse.Data.CID, err: err}
	}()

	userResult := <-result

	if userResult.err != nil {
		handleError(c, "Internal Error while getting user data from VATSIM Connect")
		return
	}

	user := &dbTypes.User{}
	if err = models.DB.First(&user, userResult.cid).Error; err != nil {
		handleError(c, "You are not part of our roster, so you are unable to login.")
		return
	}

	login.CID = user.CID
	login.Code, _ = gonanoid.New(32)
	models.DB.Save(&login)

	c.Redirect(302, fmt.Sprintf("%s?code=%s&state=%s", login.RedirectURI, login.Code, login.State))
}
