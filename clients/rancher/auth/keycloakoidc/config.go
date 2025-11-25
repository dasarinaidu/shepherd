package keycloakoidc

const (
	ConfigurationFileKey = "keycloakOIDC"
)

// Config represents the Keycloak OIDC authentication configuration structure
// used for configuring Keycloak OIDC connection parameters, user search settings,
// and group membership configuration.
type Config struct {
	ClientID              string  `json:"clientId"              yaml:"clientId"`
	ClientSecret          string  `json:"clientSecret"          yaml:"clientSecret"`
	Issuer                string  `json:"issuer"                yaml:"issuer"`
	AuthEndpoint          string  `json:"authEndpoint"          yaml:"authEndpoint"`
	RancherURL            string  `json:"rancherUrl"            yaml:"rancherUrl"`
	PrivateKey            string  `json:"privateKey"            yaml:"privateKey"`
	Certificate           string  `json:"certificate"           yaml:"certificate"`
	Users                 *Users  `json:"users"                 yaml:"users"`
	AccessMode            string  `json:"accessMode"            yaml:"accessMode"            default:"unrestricted"`
	GroupSearchEnabled    bool    `json:"groupSearchEnabled"    yaml:"groupSearchEnabled"    default:"false"`
	Scopes                string  `json:"scopes"                yaml:"scopes"                default:"openid profile email"`
	UsernameClaim         string  `json:"usernameClaim"         yaml:"usernameClaim"         default:"preferred_username"`
	GroupsClaim           string  `json:"groupsClaim"           yaml:"groupsClaim"           default:"groups"`
}

// Users represents Keycloak OIDC users, used in test scenarios for validating users search.
type Users struct {
	Admin *User `json:"admin" yaml:"admin"`
}

// User represents a Keycloak OIDC user with authentication credentials, used in test scenarios for validating user authentication.
type User struct {
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
}
