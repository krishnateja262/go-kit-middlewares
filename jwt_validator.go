package middlewares

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/golang-jwt/jwt"
)

func JWTValidator(hmacSecret string, logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			tokenString, ok := ctx.Value(JWTContextKey).(string)
			if !ok {
				return nil, ErrUnauthorized
			}

			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				if token.Method != jwt.SigningMethodHS256 {
					level.Error(logger).Log("msg", "Invalid JWT header method", "token", tokenString, "error", token.Method.Alg())
					return nil, ErrUnexpectedSigningMethod
				}

				return []byte(hmacSecret), nil
			})

			if err != nil {
				if e, ok := err.(*jwt.ValidationError); ok {
					switch {
					case e.Errors&jwt.ValidationErrorMalformed != 0:
						level.Error(logger).Log("msg", "Malformed JWT", "token", tokenString)
					case e.Errors&jwt.ValidationErrorExpired != 0:
						level.Error(logger).Log("msg", "Expired JWT", "token", tokenString)
					case e.Errors&jwt.ValidationErrorNotValidYet != 0:
						level.Error(logger).Log("msg", "Inactive JWT", "token", tokenString)
					case e.Inner != nil:
						level.Error(logger).Log("msg", "Inner JWT", "token", tokenString)
					}
				}
				level.Error(logger).Log("msg", "Error JWT", "token", tokenString, "error", err)
				return nil, ErrUnauthorized
			}

			if !token.Valid {
				level.Error(logger).Log("msg", "Invalid Token", "token", tokenString)
				return nil, ErrUnauthorized
			}

			ctx = context.WithValue(ctx, JWTClaimsContextKey, claims)
			ctx = context.WithValue(ctx, TenantID, claims.TenantID)
			ctx = context.WithValue(ctx, USERID, claims.UserId)

			return next(ctx, request)
		}
	}
}
