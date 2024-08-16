package config

import "os"

var (
	LogLevel             = os.Getenv("LOG_LEVEL")
	AuthzAllowedAuds     = os.Getenv("AUTHZ_AUDIENCES")
	AuthzAllowedOrg      = os.Getenv("AUTHZ_ORG")
	AuthzIssuer          = os.Getenv("AUTHZ_ISSUER")
	AuthzServerKeyId     = os.Getenv("AUTHZ_SERVER_KEY_ID")
	MaxConcurrentStreams = os.Getenv("MAX_CONCURRENT_STREAMS")
	PrivateKeyFile       = os.Getenv("PRIVATE_KEY_FILE")
	PubVerifyeKeyFile    = os.Getenv("PUBLIC_VERIFY_KEY_FILE")
)
