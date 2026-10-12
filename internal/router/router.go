// Package router 负责路由注册，不承载业务逻辑。
package router

import (
	"net/http"

	"banner-fingerprint/internal/handler"
)

// New 注册全部路由并返回带 panic 兜底的 http.Handler。
func New(h *handler.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fingerprint", h.Fingerprint)
	mux.HandleFunc("GET /health", h.Health)
	return recoverMiddleware(mux)
}

// recoverMiddleware 兜底捕获 handler 内的 panic，转成 500，绝不让进程崩溃。
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
