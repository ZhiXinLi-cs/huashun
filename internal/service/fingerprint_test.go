package service

import (
	"path/filepath"
	"testing"

	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/repository"
)

// TestIdentify 用真实规则文件验证核心协议识别 + unknown 兜底。
// 期望值对齐官方自测样例的响应约定：protocol 大写、confidence 分档。
func TestIdentify(t *testing.T) {
	repo, err := repository.Load(filepath.Join("..", "..", "config", "rules.yaml"))
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	svc := New(repo)

	cases := []struct {
		name    string
		in      model.FingerprintInput
		proto   string
		product string
		version string
		os      string
		conf    float64
	}{
		{"ssh-openssh", model.FingerprintInput{IP: "1.1.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		{"ssh-1.99", model.FingerprintInput{IP: "1.1.1.2", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"}, "SSH", "OpenSSH", "4.3", "", 0.95},
		{"http-nginx", model.FingerprintInput{IP: "1.1.1.3", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", "", 0.9},
		{"http-apache", model.FingerprintInput{IP: "1.1.1.4", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", "", 0.9},
		{"http-jetty-slash", model.FingerprintInput{IP: "1.1.1.5", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", "", 0.85},
		{"http-jetty-paren", model.FingerprintInput{IP: "1.1.1.6", Port: 8080, Banner: "Server: Jetty(9.4.50.v20221201)"}, "HTTP", "Jetty", "9.4.50.v20221201", "", 0.85},
		{"mysql-version", model.FingerprintInput{IP: "1.1.1.7", Port: 3306, Banner: "8.0.36-0ubuntu0.22.04.1"}, "MySQL", "MySQL", "8.0.36", "Ubuntu", 0.9},
		{"mysql-handshake", model.FingerprintInput{IP: "1.1.1.8", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"}, "MySQL", "MySQL", "8.0.32", "", 0.9},
		{"redis-info", model.FingerprintInput{IP: "1.1.1.9", Port: 6379, Banner: "# Server\r\nredis_version:7.2.4"}, "Redis", "Redis", "7.2.4", "", 0.9},
		{"redis-err", model.FingerprintInput{IP: "1.1.1.10", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", "", 0.7},
		{"redis-pong", model.FingerprintInput{IP: "1.1.1.11", Port: 6379, Banner: "+PONG"}, "Redis", "Redis", "", "", 0.8},
		{"redis-noauth", model.FingerprintInput{IP: "1.1.1.12", Port: 6379, Banner: "-NOAUTH Authentication required."}, "Redis", "Redis", "", "", 0.7},
		{"ftp-proftpd", model.FingerprintInput{IP: "1.1.1.13", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", "", 0.9},
		{"ftp-vsftpd", model.FingerprintInput{IP: "1.1.1.14", Port: 21, Banner: "220 (vsFTPd 3.0.5)"}, "FTP", "vsFTPd", "3.0.5", "", 0.9},
		{"ftp-pureftpd", model.FingerprintInput{IP: "1.1.1.15", Port: 21, Banner: "220 Welcome to Pure-FTPd"}, "FTP", "Pure-FTPd", "", "", 0.85},
		{"tls-unknown", model.FingerprintInput{IP: "1.1.1.16", Port: 9999, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, "unknown", "", "", "", 0},
		{"iis-unknown", model.FingerprintInput{IP: "1.1.1.17", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, "unknown", "", "", "", 0},
		{"unknown", model.FingerprintInput{IP: "2.2.2.2", Port: 9999, Banner: "some totally unknown service"}, "unknown", "", "", "", 0},
		{"empty-banner", model.FingerprintInput{IP: "2.2.2.3", Port: 9999, Banner: ""}, "unknown", "", "", "", 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := svc.Identify(c.in)
			if got.Protocol != c.proto || got.Product != c.product || got.Version != c.version ||
				got.OSHint != c.os || got.Confidence != c.conf {
				t.Errorf("识别结果不符:\n got  %+v\n want proto=%s product=%s version=%s os=%s conf=%v",
					got, c.proto, c.product, c.version, c.os, c.conf)
			}
		})
	}
}

// TestIdentifyAllKeepsOrder 验证批量识别结果与输入顺序一致。
func TestIdentifyAllKeepsOrder(t *testing.T) {
	repo, err := repository.Load(filepath.Join("..", "..", "config", "rules.yaml"))
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	svc := New(repo)

	inputs := []model.FingerprintInput{
		{IP: "a", Port: 1, Banner: "SSH-2.0-OpenSSH_9.0"},
		{IP: "b", Port: 2, Banner: "???"},
		{IP: "c", Port: 3, Banner: "redis_version:7.0.0"},
	}
	results := svc.IdentifyAll(inputs)
	if len(results) != len(inputs) {
		t.Fatalf("结果数量不符: %d", len(results))
	}
	for i := range inputs {
		if results[i].IP != inputs[i].IP || results[i].Port != inputs[i].Port {
			t.Errorf("第 %d 条结果顺序/字段不符: %+v", i, results[i])
		}
	}
}
