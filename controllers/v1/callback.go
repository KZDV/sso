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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	dbTypes "github.com/kzdv/api/pkg/database/types"
	"github.com/kzdv/sso/database/models"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"gorm.io/gorm"
	"hawton.dev/log4g"
)

type Result struct {
	UserResponse UserResponse
	err          error
}

type UserResponse struct {
	CID      string               `json:"cid"`
	Personal UserResponsePersonal `json:"personal"`
	Vatsim   VatsimDetails        `json:"vatsim"`
}

type UserResponsePersonal struct {
	FirstName string `json:"name_first"`
	LastName  string `json:"name_last"`
	FullName  string `json:"name_full"`
	Email     string `json:"email"`
}

type VatsimDetails struct {
	Rating VatsimDetailsRating `json:"rating"`
}

type VatsimDetailsRating struct {
	ID    int    `json:"id"`
	Long  string `json:"long"`
	Short string `json:"short"`
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
	returnUri := fmt.Sprintf("%s://%s/oauth/callback", scheme, c.Request.Host)

	result := make(chan Result)
	go func() {
		tokenUrl := fmt.Sprintf("%s%s", os.Getenv("VATSIM_BASE_URL"), os.Getenv("VATSIM_TOKEN_PATH"))

		data := map[string]interface{}{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  returnUri,
			"client_id":     atoi(os.Getenv("VATSIM_OAUTH_CLIENT_ID")),
			"client_secret": os.Getenv("VATSIM_OAUTH_CLIENT_SECRET"),
			"scopes":        strings.Split(os.Getenv("VATSIM_OAUTH_SCOPES"), " "),
		}

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

		if request.StatusCode > 399 {
			result <- Result{err: fmt.Errorf("error %d received from vatsim: %s", request.StatusCode, string(body))}
			return
		}

		accessToken := &VatsimAccessToken{}
		if err = json.Unmarshal(body, accessToken); err != nil {
			result <- Result{err: err}
			return
		}

		if accessToken.AccessToken == "" {
			result <- Result{err: fmt.Errorf("no access token received")}
			return
		}

		userRequest, err := http.NewRequest("GET", fmt.Sprintf("%s%s", os.Getenv("VATSIM_BASE_URL"), os.Getenv("VATSIM_USER_INFO_PATH")), nil)
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

		if userResponse.StatusCode > 399 {
			result <- Result{err: fmt.Errorf("error %d received from vatsim: %s", userResponse.StatusCode, string(userBody))}
			return
		}

		vatsimResponse := &VatsimResponse{}
		if err = json.Unmarshal(userBody, vatsimResponse); err != nil {
			result <- Result{err: err}
			return
		}

		result <- Result{UserResponse: vatsimResponse.Data, err: err}
	}()

	userResult := <-result

	if userResult.err != nil {
		log4g.Category("controllers/callback").Error("Error getting user from Vatsim: %s", userResult.err.Error())
		handleError(c, "Internal Error while getting user data from VATSIM Connect")
		return
	}

	log4g.Category("controllers/callback").Debug("Got user from Vatsim: %+v", userResult.UserResponse)
	user := &dbTypes.User{}
	if err = models.DB.Where(&dbTypes.User{CID: uint(atoi(userResult.UserResponse.CID))}).First(&user).Error; err != nil {
		if errors.Is(gorm.ErrRecordNotFound, err) {
			log4g.Category("controllers/callback").Debug("User not found in db, creating new user")
			// @TODO: Move this to an API package when the new monolith API is written
			go func(user UserResponse) {
				rating := &dbTypes.Rating{}
				if err := models.DB.Where(&dbTypes.Rating{ID: user.Vatsim.Rating.ID}).First(&rating).Error; err != nil {
					log4g.Category("controllers/callback").Error("Error getting rating from db: %s", err.Error())
					return
				}

				newUser := &dbTypes.User{
					CID:              uint(atoi(user.CID)),
					FirstName:        user.Personal.FirstName,
					LastName:         user.Personal.LastName,
					Email:            user.Personal.Email,
					ControllerType:   dbTypes.ControllerTypeOptions["none"],
					DelCertification: dbTypes.CertificationOptions["none"],
					GndCertification: dbTypes.CertificationOptions["none"],
					LclCertification: dbTypes.CertificationOptions["none"],
					AppCertification: dbTypes.CertificationOptions["none"],
					CtrCertification: dbTypes.CertificationOptions["none"],
					RatingID:         user.Vatsim.Rating.ID,
					Rating:           *rating,
					Status:           dbTypes.ControllerStatusOptions["none"],
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}
				if err := models.DB.Create(&newUser).Error; err != nil {
					log4g.Category("controllers/callback").Error("Error creating user in db: %s", err.Error())
					return
				}
			}(userResult.UserResponse)
		} else {
			log4g.Category("controllers/callback").Error("Error getting user from db: %s", err.Error())
			handleError(c, "Internal Error while getting user data from VATSIM Connect")
			return
		}
	}

	log4g.Category("controllers/callback").Debug("Got user from db: %+v", user)

	login.CID = uint(atoi(userResult.UserResponse.CID))
	login.Code, _ = gonanoid.New(32)
	models.DB.Save(&login)

	c.Redirect(302, fmt.Sprintf("%s?code=%s&state=%s", login.RedirectURI, login.Code, login.State))
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
