package middlewares

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
	metahttp "github.com/krishnateja262/meta-http/pkg/meta_http"
)

func Logger(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			request_id, ok := ctx.Value(metahttp.RequestID).(string)
			if !ok {
				request_id = ""
			}

			startTime := time.Now()
			logger.Log("msg", "Server request started", "request", request, string(metahttp.RequestID), request_id)
			res, err := next(ctx, request)
			elapsedTime := time.Since(startTime)
			logger.Log("msg", "Server request ended", "response", res, string(metahttp.RequestID), request_id, "duration", elapsedTime.Milliseconds())
			return res, err
		}
	}
}
