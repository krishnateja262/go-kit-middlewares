package middlewares

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
	metahttp "github.com/krishnateja262/meta-http/pkg/meta_http"
)

type Merchant struct {
	ID         string    `json:"id,omitempty"`
	Email      string    `json:"email"`
	OTP        string    `json:"otp"`
	IsVerfied  bool      `json:"isVerified"`
	CreatedAt  time.Time `json:"createdAt,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt,omitempty"`
	WebhookUrl string    `json:"webhookUrl"`
	APIKey     string    `json:"apiKey"`
	APISecret  string    `json:"apiSecret"`
}

type MerchantAPIResponse struct {
	Success bool     `json:"success"`
	Data    Merchant `json:"data"`
}

type KeyValidator interface {
	ValidateKey(ctx context.Context, apikey string) (Merchant, error)
}

type KeyStore interface {
	Put(key string, mer Merchant) error
	Get(key string) (Merchant, error)
}

type DefaultValidator struct {
	client *metahttp.Client
	store  KeyStore
}

type DefaultStore struct {
	data map[string]Merchant
}

func (store DefaultStore) Put(key string, mer Merchant) error {
	store.data[key] = mer
	return nil
}

func (store DefaultStore) Get(key string) (Merchant, error) {
	if mer, ok := store.data[key]; ok {
		return mer, nil
	}

	return Merchant{}, ErrNotFound
}

func NewValidator(client *metahttp.Client) KeyValidator {
	return &DefaultValidator{
		client: client,
		store: DefaultStore{
			data: map[string]Merchant{},
		},
	}
}

func NewValidatorWithStore(client *metahttp.Client, store KeyStore) KeyValidator {
	return &DefaultValidator{
		client: client,
		store:  store,
	}
}

func (svc DefaultValidator) fetchMerchantDetails(ctx context.Context, apikey string) (Merchant, error) {
	var res MerchantAPIResponse
	req := map[string]string{"apikey": apikey}
	err := svc.client.Post(ctx, "", map[string]string{}, req, &res)

	if err != nil {
		return Merchant{}, err
	}

	return res.Data, nil
}

func (svc DefaultValidator) ValidateKey(ctx context.Context, apikey string) (Merchant, error) {
	mer, err := svc.store.Get(apikey)

	if err != nil && err == ErrNotFound {
		mer, err = svc.fetchMerchantDetails(ctx, apikey)

		if err != nil {
			return Merchant{}, err
		}

		svc.store.Put(apikey, mer)
		return mer, nil
	}

	if err != nil {
		return Merchant{}, err
	}

	return mer, nil
}

func MerchantAPIKeyValidator(svc KeyValidator, logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			apikey, ok := ctx.Value(metahttp.MerchantAPIKey).(string)
			if !ok {
				return nil, ErrUnauthorized
			}
			mer, err := svc.ValidateKey(ctx, apikey)

			if err != nil || mer.ID == "" {
				return nil, ErrUnauthorized
			}
			ctx = context.WithValue(ctx, metahttp.TenantID, mer.ID)
			return next(ctx, request)
		}
	}
}
