package middlewares

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
	metahttp "github.com/krishnateja262/meta-http/pkg/meta_http"
)

func TenantIdValidator(pathParam string, logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			pathParams := ctx.Value(PathParamsContextKey).(map[string]string)
			id := pathParams[pathParam]

			tenantId := ctx.Value(metahttp.TenantID).(string)

			request_id, ok := ctx.Value(metahttp.RequestID).(string)
			if !ok {
				request_id = ""
			}

			if ok && tenantId != id {
				logger.Log("level", "error", "msg", "Tenant ID does not match with claims ID", "tenantId", id, "claimsId", tenantId, string(metahttp.RequestID), request_id)
				return nil, ErrUnauthorized
			}

			return next(ctx, request)
		}
	}
}
