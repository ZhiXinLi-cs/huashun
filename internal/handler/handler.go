// Package handler 处理 HTTP 请求与响应（参数解析、校验、组装响应）。
package handler

import (
	"encoding/json"
	"net/http"

	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/service"
)

// Handler 持有识别引擎的引用。
type Handler struct {
	svc *service.Service
}

// New 构造 Handler。
func New(svc *service.Service) *Handler {
	return &Handler{svc: svc}
}

// Fingerprint 处理 POST /fingerprint：批量识别。
func (h *Handler) Fingerprint(w http.ResponseWriter, r *http.Request) {
	// 限制请求体大小，避免恶意超大请求。
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var inputs []model.FingerprintInput
	if err := json.NewDecoder(r.Body).Decode(&inputs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	writeJSON(w, http.StatusOK, h.svc.IdentifyAll(inputs))
}

// Health 处理 GET /health：健康检查。
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
