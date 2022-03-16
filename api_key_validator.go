package middlewares

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
)

func APIKeyValidator(key string, logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			apiKey, ok := ctx.Value(APIContextKey).(string)
			if !ok {
				return nil, ErrUnauthorized
			}

			if apiKey != key {
				return nil, ErrUnauthorized
			}

			return next(ctx, request)
		}
	}
}
