package config

const (
	DefaultMaxStreams uint32 = 1
	DefaultPort       int    = 9001
	JwtExpireOffset          = 60 * 60
	DefaultKeyfile    string = "/data/certs/key.pem"
	DefaultVerifyfile string = "/data/certs/pub.pem"
)
