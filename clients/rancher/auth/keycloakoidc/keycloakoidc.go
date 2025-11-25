package keycloakoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"
)

type Operations interface {
	Enable() error
	Disable() error
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

// Enable is a method of KeycloakOIDC, makes a request to the action with the given
// configuration values
func (k *Client) Enable() error {
	var jsonResp map[string]interface{}
	url := k.newActionURL("testAndApply")

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

// Update is a method of KeycloakOIDC, makes an update with the given configuration values
func (k *Client) Update(
	existing, updates *management.AuthConfig,
) (*management.AuthConfig, error) {
	return k.client.AuthConfig.Update(existing, updates)
}

// Disable is a method of KeycloakOIDC, makes a request to disable Keycloak OIDC
func (k *Client) Disable() error {
	var jsonResp map[string]any
	url := k.newActionURL("disable")
	disableActionInput := k.newDisableInput()

	return k.client.Ops.DoModify("POST", url, &disableActionInput, &jsonResp)
}

func (k *Client) newActionURL(action string) string {
	return fmt.Sprintf(
		"%v/%v/%v?action=%v",
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
	}

	usernameClaim := k.Config.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "preferred_username"
	}

	groupsClaim := k.Config.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	// Create the configuration as a map to avoid type issues
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

func (k *Client) newDisableInput() map[string]interface{} {
	return map[string]interface{}{
		"enabled": false,
	}
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
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
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
		Bytes: certBytes,
	})

	return string(privateKeyPEM), string(certPEM), nil
}
