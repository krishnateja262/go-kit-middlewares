package middlewares

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
)

func TenantIdValidator(pathParam string, logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			pathParams := ctx.Value(PathParamsContextKey).(map[string]string)
			id, ok := pathParams[pathParam]

			tenantId := ctx.Value(TenantID).(string)

			if ok && tenantId != id {
				logger.Log("level", "error", "msg", "Tenant ID does not match with claims ID", "tenantId", id, "claimsId", tenantId)
				return nil, ErrUnauthorized
			}

			return next(ctx, request)
		}
	}
}
