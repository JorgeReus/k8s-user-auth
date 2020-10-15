package test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"testing"
)

type OpenIdConfig struct {
	Issuer                                string
	Authorization_endpoint                string
	Token_endpoint                        string
	Jwks_uri                              string
	Userinfo_endpoint                     string
	Device_authorization_endpoint         string
	Grant_types_supported                 []string
	Response_types_supported              []string
	Subject_types_supported               []string
	Id_token_signing_alg_values_supported []string
	Scopes_supported                      []string
	Token_endpoint_auth_methods_supported []string
	Claims_supported                      []string
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func TestDexDeploy(t *testing.T) {
	t.Parallel()
	terraformOptions := &terraform.Options{
		TerraformDir: "../",
	}

	terraform.InitAndApplyAndIdempotentE(t, terraformOptions)
	url := terraform.Output(t, terraformOptions, "url")

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Get(fmt.Sprintf("%s/dex/.well-known/openid-configuration", url))
	check(err)
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	var openidConfig OpenIdConfig
	json.Unmarshal(body, &openidConfig)
	// Verify that dex supports the email claim
	assert.Contains(t, openidConfig.Claims_supported, "email")
	// Verify that dex supports the groups scope
	assert.Contains(t, openidConfig.Scopes_supported, "groups")
}
