package oidc

const (
	ConfigurationFileKey                 = "oidc"
	OIDCProviderFeatureFlag              = "oidc-provider"
	DefaultTokenExpirationSeconds        = 3600
	DefaultRefreshTokenExpirationSeconds = 86400
)

// DefaultAutomationScopes is the scope list requested by the OIDC test automation when the test config does not specify one.
var DefaultAutomationScopes = []string{
	"openid",
	"profile",
	"offline_access",
	"rancher:users",
}

// Config is the test-side OIDC configuration loaded from the cattle config file under the "oidc" key.
type Config struct {
	ClientName                    string   `json:"clientName" yaml:"clientName"`
	RedirectURI                   string   `json:"redirectURI" yaml:"redirectURI"`
	Scopes                        []string `json:"scopes" yaml:"scopes"`
	TokenExpirationSeconds        int      `json:"tokenExpirationSeconds" yaml:"tokenExpirationSeconds"`
	RefreshTokenExpirationSeconds int      `json:"refreshTokenExpirationSeconds" yaml:"refreshTokenExpirationSeconds"`
	AdminUsername                 string   `json:"adminUsername" yaml:"adminUsername"`
	AdminPassword                 string   `json:"adminPassword" yaml:"adminPassword"`
}
