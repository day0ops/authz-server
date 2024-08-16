package authz

import (
	"context"
	"crypto/rsa"
	"github.com/day0ops/istio-authz/authz-server/pkg/config"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
	rpc "google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"slices"
	"strings"
	"time"
)

type AuthorizationServer struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Log        *zap.Logger
}

type IncomingJwtClaims struct {
	Org string `json:"org"`
	jwt.StandardClaims
}

type OutgoingJwtClaims struct {
	Aud []string `json:"aud"` // https://github.com/dgrijalva/jwt-go/pull/308
	jwt.StandardClaims
}

func (a *AuthorizationServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	a.Log.Info("authorizing request")

	authHeader, ok := req.Attributes.Request.Http.Headers["authorization"]
	if !ok {
		a.Log.Warn("unable to find Authorization Header")
		return returnUnAuthenticated("unable to find Authorization Header"), nil
	}
	var splitToken []string
	a.Log.Info("authorization Header", zap.String("authHeader", authHeader))

	splitToken = strings.Split(authHeader, "Bearer ")
	if splitToken == nil || len(splitToken) != 2 {
		a.Log.Warn("unable to parse Header")
		return returnUnAuthenticated("unable to parse Authorization Header"), nil
	}

	if len(splitToken) == 2 {
		token := splitToken[1]

		if token != "" {
			audVerifyList := strings.Split(config.AuthzAllowedAuds, ",")
			validatingClaims := a.parseAccessTokenIfValid(token)
			if validatingClaims != nil && validatingClaims.Org == config.AuthzAllowedOrg && slices.Contains(audVerifyList, validatingClaims.Audience) {
				claims := OutgoingJwtClaims{
					audVerifyList,
					jwt.StandardClaims{
						Issuer:    config.AuthzIssuer,
						Subject:   config.AuthzIssuer,
						IssuedAt:  time.Now().Unix(),
						ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
					},
				}

				a.Log.Info("using Claim", zap.Any("claims", claims))
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				token.Header["kid"] = config.AuthzServerKeyId
				ss, err := token.SignedString(a.PrivateKey)
				if err != nil {
					return returnUnAuthenticated("Unable to generate JWT"), nil
				}

				a.Log.Info("issuing outbound Header", zap.String("header", ss))

				return &authv3.CheckResponse{
					Status: &rpcstatus.Status{
						Code: int32(rpc.Code_OK),
					},
					HttpResponse: &authv3.CheckResponse_OkResponse{
						OkResponse: &authv3.OkHttpResponse{
							Headers: []*corev3.HeaderValueOption{
								{
									Header: &corev3.HeaderValue{
										Key:   "Authorization",
										Value: "Bearer " + ss,
									},
								},
							},
						},
					},
				}, nil
			} else {
				a.Log.Warn("unable to validate JWT")
				return returnPermissionDenied("Permission Denied"), nil
			}
		} else {
			a.Log.Warn("authorization Header missing")
			return returnPermissionDenied("Permission Denied"), nil
		}
	}
	return returnUnAuthenticated("authorization header not provided"), nil
}

func (a *AuthorizationServer) parseAccessTokenIfValid(token string) *IncomingJwtClaims {
	var claims IncomingJwtClaims
	tkn, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return a.PublicKey, nil
	})

	if err != nil {
		v, _ := err.(*jwt.ValidationError)
		if v.Errors == jwt.ValidationErrorSignatureInvalid {
			a.Log.Warn("jwt signature invalid")
			return nil
		}
	}

	if tkn != nil {
		vErr := tkn.Claims.Valid()
		if vErr != nil {
			v, _ := vErr.(*jwt.ValidationError)
			// we only care about expiries for now
			if v.Errors == jwt.ValidationErrorExpired && claims.ExpiresAt <= time.Now().Unix()-(config.JwtExpireOffset) {
				a.Log.Warn("jwt is expired and no longer valid")
				return nil
			}
		}
	}

	return &claims
}

func returnUnAuthenticated(message string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.Code_UNAUTHENTICATED),
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode_Forbidden,
				},
				Body: message,
			},
		},
	}
}

func returnPermissionDenied(message string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.Code_PERMISSION_DENIED),
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode_Unauthorized,
				},
				Body: message,
			},
		},
	}
}
