package keycloakoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"
)

type Operations interface {
	Enable() error
	Disable() error
	CompleteOAuthFlow(code string) error
	Update(existing, updates *management.AuthConfig) (*management.AuthConfig, error)
}

const (
	resourceType = "keycloakoidc"
	schemaType   = "keyCloakOIDCConfigs"
)

type Client struct {
	client  *management.Client
	session *session.Session
	Config  *Config
}

// NewKeycloakOIDC constructs KeycloakOIDC struct after it reads Keycloak OIDC from the configuration file
func NewKeycloakOIDC(client *management.Client, session *session.Session) (*Client, error) {
	oidcConfig := new(Config)
	config.LoadConfig(ConfigurationFileKey, oidcConfig)

	return &Client{
		client:  client,
		session: session,
		Config:  oidcConfig,
	}, nil
}

// Enable is a method of KeycloakOIDC, makes a request to configure and validate the OIDC settings
// Note: This creates the configuration but does not fully enable (requires OAuth flow)
func (k *Client) Enable() error {
	var jsonResp map[string]interface{}
	url := k.newActionURL("configureTest")

	enableActionInput, err := k.newEnableInputFromConfig()
	if err != nil {
		return err
	}

	err = k.client.Ops.DoModify("POST", url, enableActionInput, &jsonResp)
	if err != nil {
		return err
	}

	k.session.RegisterCleanupFunc(func() error {
		return k.Disable()
	})

	return nil
}

// CompleteOAuthFlow completes the OIDC setup with the OAuth authorization code
// This is called after the user completes the OAuth flow in the browser
func (k *Client) CompleteOAuthFlow(code string) error {
	var jsonResp map[string]interface{}
	url := k.newActionURL("testAndApply")

	configInput, err := k.newEnableInputFromConfig()
	if err != nil {
		return err
	}

	// Wrap in the structure Rancher expects for testAndApply
	applyInput := map[string]interface{}{
		"enabled":    true,
		"code":       code,
		"oidcConfig": configInput,
	}

	return k.client.Ops.DoModify("POST", url, applyInput, &jsonResp)
}

// Disable is a method of KeycloakOIDC, makes a request to disable Keycloak OIDC
func (k *Client) Disable() error {
	authConfig, err := k.client.AuthConfig.ByID(resourceType)
	if err != nil {
		// If config doesn't exist, nothing to disable
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "NotFound") {
			return nil
		}
		return fmt.Errorf("failed to get auth config: %w", err)
	}

	authConfig.Enabled = false
	_, err = k.client.AuthConfig.Update(authConfig, authConfig)
	if err != nil {
		return fmt.Errorf("failed to disable auth config: %w", err)
	}

	return nil
}

// Update is a method of KeycloakOIDC, makes a request to update an auth config.
func (k *Client) Update(existing, updates *management.AuthConfig) (*management.AuthConfig, error) {
	return k.client.AuthConfig.Update(existing, updates)
}

// newActionURL constructs the API URL for a given action
func (k *Client) newActionURL(action string) string {
	return fmt.Sprintf(
		"%s/%s/%s?action=%s",
		k.client.Opts.URL,
		schemaType,
		resourceType,
		action,
	)
}

func (k *Client) newEnableInputFromConfig() (map[string]interface{}, error) {
	if k.Config.Issuer == "" {
		return nil, fmt.Errorf("keycloak OIDC Issuer is empty, please provide it")
	}

	if k.Config.ClientID == "" {
		return nil, fmt.Errorf("keycloak OIDC ClientID is empty, please provide it")
	}

	if k.Config.ClientSecret == "" {
		return nil, fmt.Errorf("keycloak OIDC ClientSecret is empty, please provide it")
	}

	// Generate private key and certificate if not provided
	privateKey := k.Config.PrivateKey
	certificate := k.Config.Certificate

	if privateKey == "" || certificate == "" {
		generatedKey, generatedCert, err := generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		privateKey = generatedKey
		certificate = generatedCert
	}

	// Derive endpoints from issuer if not provided
	authEndpoint := k.Config.AuthEndpoint
	if authEndpoint == "" {
		authEndpoint = fmt.Sprintf("%s/protocol/openid-connect/auth", k.Config.Issuer)
	}

	rancherURL := k.Config.RancherURL
	if rancherURL == "" {
		rancherURL = fmt.Sprintf("%s/verify-auth", k.client.Opts.URL)
	}

	scopes := k.Config.Scopes
	if scopes == "" {
		scopes = "openid profile email"
	} else {
		// Ensure openid is always present
		if !strings.Contains(scopes, "openid") {
			scopes = "openid " + scopes
		}
	}

	usernameClaim := k.Config.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "preferred_username"
	}

	groupsClaim := k.Config.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	// Create the configuration as a map
	enableInput := map[string]interface{}{
		"enabled":            true,
		"accessMode":         k.Config.AccessMode,
		"clientId":           k.Config.ClientID,
		"clientSecret":       k.Config.ClientSecret,
		"issuer":             k.Config.Issuer,
		"authEndpoint":       authEndpoint,
		"rancherUrl":         rancherURL,
		"privateKey":         privateKey,
		"certificate":        certificate,
		"groupSearchEnabled": k.Config.GroupSearchEnabled,
		"scopes":             scopes,
		"usernameClaim":      usernameClaim,
		"groupsClaim":        groupsClaim,
	}

	return enableInput, nil
}

// generateSelfSignedCert generates a self-signed certificate and private key for OIDC
func generateSelfSignedCert() (string, string, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Rancher Test"},
			CommonName:   "Rancher Keycloak OIDC Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(privateKeyPEM), string(certPEM), nil
}
