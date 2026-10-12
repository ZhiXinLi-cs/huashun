// server 是 Banner 指纹识别服务端，提供批量识别与健康检查接口。
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"banner-fingerprint/internal/handler"
	"banner-fingerprint/internal/repository"
	"banner-fingerprint/internal/router"
	"banner-fingerprint/internal/service"
)

func main() {
	rulesFile := os.Getenv("RULES_FILE")
	if rulesFile == "" {
		rulesFile = "config/rules.yaml"
	}

	repo, err := repository.Load(rulesFile)
	if err != nil {
		log.Fatalf("加载规则失败: %v", err)
	}

	svc := service.New(repo)
	h := handler.New(svc)
	r := router.New(h)

	addr := os.Getenv("SERVER_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("banner fingerprint server listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务启动失败: %v", err)
	}
}
