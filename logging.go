package middlewares

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
)

func Logger(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			logger.Log("msg", "Server request started", "request", request)
			res, err := next(ctx, request)
			logger.Log("msg", "Server request ended", "response", res)
			return res, err
		}
	}
}
