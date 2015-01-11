// Copyright 2014 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	goauth2 "code.google.com/p/goauth2/oauth"
	"github.com/mmitton/ldap"
	"github.com/tsuru/config"
	"github.com/tsuru/tsuru/auth"
	"github.com/tsuru/tsuru/auth/native"
	tsuruErrors "github.com/tsuru/tsuru/errors"
	"github.com/tsuru/tsuru/log"
)

var (
	ErrMissingCodeError       = &tsuruErrors.ValidationError{Message: "You must provide code to login"}
	ErrMissingCodeRedirectUrl = &tsuruErrors.ValidationError{Message: "You must provide the used redirect url to login"}
	ErrEmptyAccessToken       = &tsuruErrors.NotAuthorizedError{Message: "Couldn't convert code to access token."}
	ErrEmptyUserEmail         = &tsuruErrors.NotAuthorizedError{Message: "Couldn't parse user email."}
)

type LDAPParser interface {
	Parse(infoResponse *http.Response) (string, error)
}

type LDAPScheme struct {
	BaseConfig   goauth2.Config
	InfoUrl      string
	CallbackPort int
	Parser       LDAPParser
}

type DBTokenCache struct {
	scheme *LDAPScheme
}

func (c *DBTokenCache) Token() (*goauth2.Token, error) {
	return nil, nil
}

func (c *DBTokenCache) PutToken(t *goauth2.Token) error {
	if t.AccessToken == "" {
		return ErrEmptyAccessToken
	}
	var email string
	if t.Extra == nil || t.Extra["email"] == "" {
		conf, err := c.scheme.loadConfig()
		if err != nil {
			return err
		}
		transport := &goauth2.Transport{Config: &conf}
		transport.Token = t
		client := transport.Client()
		response, err := client.Get(c.scheme.InfoUrl)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		email, err = c.scheme.Parser.Parse(response)
		if email == "" {
			return ErrEmptyUserEmail
		}
		user, err := auth.GetUserByEmail(email)
		if err != nil {
			if err != auth.ErrUserNotFound {
				return err
			}
			registrationEnabled, _ := config.GetBool("auth:user-registration")
			if !registrationEnabled {
				return err
			}
			user = &auth.User{Email: email}
			err := user.Create()
			if err != nil {
				return err
			}
		}
		err = user.CreateOnGandalf()
		if err != nil {
			log.Errorf("Ignored error trying to create user on gandalf: %s", err.Error())
		}
		t.Extra = make(map[string]string)
		t.Extra["email"] = email
	}
	return makeToken(t).save()
}

func init() {
	auth.RegisterScheme("ldap", &LDAPScheme{})
}

// This method loads basic config and returns a copy of the
// config object.
func (s *LDAPScheme) loadConfig() (goauth2.Config, error) {
	if s.BaseConfig.ClientId != "" {
		return s.BaseConfig, nil
	}
	if s.Parser == nil {
		s.Parser = s
	}
	var emptyConfig goauth2.Config
	clientId, err := config.GetString("auth:oauth:client-id")
	if err != nil {
		return emptyConfig, err
	}
	clientSecret, err := config.GetString("auth:oauth:client-secret")
	if err != nil {
		return emptyConfig, err
	}
	scope, err := config.GetString("auth:oauth:scope")
	if err != nil {
		return emptyConfig, err
	}
	authURL, err := config.GetString("auth:oauth:auth-url")
	if err != nil {
		return emptyConfig, err
	}
	tokenURL, err := config.GetString("auth:oauth:token-url")
	if err != nil {
		return emptyConfig, err
	}
	infoURL, err := config.GetString("auth:oauth:info-url")
	if err != nil {
		return emptyConfig, err
	}
	callbackPort, err := config.GetInt("auth:oauth:callback-port")
	if err != nil {
		log.Debugf("auth:oauth:callback-port not found using random port: %s", err)
	}
	s.InfoUrl = infoURL
	s.CallbackPort = callbackPort
	s.BaseConfig = goauth2.Config{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Scope:        scope,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		TokenCache:   &DBTokenCache{s},
	}
	return s.BaseConfig, nil
}

func (s *LDAPScheme) Login(params map[string]string) (auth.Token, error) {
	fmt.Printf("(s *LDAPScheme) Login(%+v): Entered\n", params)
	fmt.Printf("ldap.Dial = %+v\n", ldap.Dial)
	ldap_server := "dc1-mp.corp.surveymonkey.com"
	ldap_port := 389
	ldapConn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldap_server, ldap_port))
	if err != nil {
    fmt.Printf(err.Error())
		return nil, err
	}
	fmt.Printf("Connected. ldapConn = %+v\n", ldapConn)
  // defer ldapConn.Close()

var base_dn string = "dc=umich,dc=edu"
var filter []string = []string{
  "(cn=cis-fac)",
  "(&(objectclass=rfc822mailgroup)(cn=*Computer*))",
  "(&(objectclass=rfc822mailgroup)(cn=*Mathematics*))"}
var attributes []string = []string{
  "cn",
  "description"}

	fmt.Printf("Doing an LDAP search...\n")
  search_request := ldap.NewSearchRequest(
    base_dn,
    ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
    filter[0],
    attributes,
    nil)

  sr, err := ldapConn.Search(search_request)
  if err != nil {
    fmt.Printf(err.Error())
    return nil, err
  }

  fmt.Printf("TestSearch: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))

	return nil, fmt.Errorf("LDAPScheme.Login: Not implemented yet.")
}

func (s *LDAPScheme) AppLogin(appName string) (auth.Token, error) {
	nativeScheme := native.NativeScheme{}
	return nativeScheme.AppLogin(appName)
}

func (s *LDAPScheme) Logout(token string) error {
	return deleteToken(token)
}

func (s *LDAPScheme) Auth(header string) (auth.Token, error) {
	token, err := getToken(header)
	if err != nil {
		nativeScheme := native.NativeScheme{}
		token, nativeErr := nativeScheme.Auth(header)
		if nativeErr == nil && token.IsAppToken() {
			return token, nil
		}
		return nil, err
	}
	config, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	transport := goauth2.Transport{Config: &config}
	transport.Token = &token.Token
	client := transport.Client()
	rsp, err := client.Get(s.InfoUrl)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	return makeToken(transport.Token), nil
}

func (s *LDAPScheme) Name() string {
	return "ldap"
}

func (s *LDAPScheme) Info() (auth.SchemeInfo, error) {
	config, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	config.RedirectURL = "__redirect_url__"
	return auth.SchemeInfo{"authorizeUrl": config.AuthCodeURL(""), "port": strconv.Itoa(s.CallbackPort)}, nil
}

func (s *LDAPScheme) Parse(infoResponse *http.Response) (string, error) {
	user := struct {
		Email string `json:"email"`
	}{}
	err := json.NewDecoder(infoResponse.Body).Decode(&user)
	if err != nil {
		return user.Email, err
	}
	return user.Email, nil
}

func (s *LDAPScheme) Create(user *auth.User) (*auth.User, error) {
	err := user.Create()
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *LDAPScheme) Remove(u *auth.User) error {
	err := deleteAllTokens(u.Email)
	if err != nil {
		return err
	}
	return u.Delete()
}
