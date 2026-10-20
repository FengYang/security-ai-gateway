package a2aregistry

import (
	"fmt"
	"net/http"
)

// regError 是控制面 API 错误（冻结 §5.6 错误码表）。
// 错误体统一为 {"error":{"code","message","details","request_id"}}。
type regError struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
}

// Error 实现 error。
func (e *regError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// newErr 构造控制面错误。
func newErr(status int, code, format string, args ...any) *regError {
	return &regError{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// withDetails 附加错误细节（不回显卡正文/密钥材料）。
func (e *regError) withDetails(d map[string]any) *regError {
	e.Details = d
	return e
}

// 常用错误码（冻结 §5.6）。
const (
	codeInvalidRequest      = "invalid_request"
	codeUnauthorized        = "unauthorized"
	codeForbidden           = "forbidden"
	codeNotFound            = "not_found"
	codeNameConflict        = "name_conflict"
	codeIdempotencyConflict = "idempotency_conflict"
	codeRevisionConflict    = "revision_conflict"
	codePreconditionRequired = "precondition_required"
	codePayloadTooLarge     = "payload_too_large"
	codeValidationFailed    = "validation_failed"
	codeSignatureInvalid    = "signature_invalid"
	codeUntrustedKey        = "untrusted_key"
	codeJKUNotAllowed       = "jku_not_allowed"
	codeRegistryUnavailable = "registry_unavailable"
	codeInternal            = "internal"
)

// errInvalid 400。
func errInvalid(format string, args ...any) *regError {
	return newErr(http.StatusBadRequest, codeInvalidRequest, format, args...)
}

// errUnauthorized 401。
func errUnauthorized(format string, args ...any) *regError {
	return newErr(http.StatusUnauthorized, codeUnauthorized, format, args...)
}

// errForbidden 403。
func errForbidden(format string, args ...any) *regError {
	return newErr(http.StatusForbidden, codeForbidden, format, args...)
}

// errNotFound 404。
func errNotFound(format string, args ...any) *regError {
	return newErr(http.StatusNotFound, codeNotFound, format, args...)
}

// errConflict 409。
func errConflict(code, format string, args ...any) *regError {
	return newErr(http.StatusConflict, code, format, args...)
}

// errPreconditionFailed 412。
func errPreconditionFailed(format string, args ...any) *regError {
	return newErr(http.StatusPreconditionFailed, codeRevisionConflict, format, args...)
}

// errPreconditionRequired 428。
func errPreconditionRequired(format string, args ...any) *regError {
	return newErr(http.StatusPreconditionRequired, codePreconditionRequired, format, args...)
}

// errPayloadTooLarge 413。
func errPayloadTooLarge(format string, args ...any) *regError {
	return newErr(http.StatusRequestEntityTooLarge, codePayloadTooLarge, format, args...)
}

// errValidation 422（校验/信任拒绝；code 可为签名/信任类子码）。
func errValidation(code, format string, args ...any) *regError {
	return newErr(http.StatusUnprocessableEntity, code, format, args...)
}

// errUnavailable 503。
func errUnavailable(format string, args ...any) *regError {
	return newErr(http.StatusServiceUnavailable, codeRegistryUnavailable, format, args...)
}

// errInternal 500。
func errInternal(format string, args ...any) *regError {
	return newErr(http.StatusInternalServerError, codeInternal, format, args...)
}
