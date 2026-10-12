package service

import (
	"path/filepath"
	"testing"

	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/repository"
)

// TestIdentify 用真实规则文件验证核心协议识别 + unknown 兜底。
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
	}{
		{"ssh-openssh", model.FingerprintInput{IP: "1.1.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}, "ssh", "OpenSSH", "8.9p1", "Ubuntu"},
		{"http-nginx", model.FingerprintInput{IP: "1.1.1.2", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}, "http", "nginx", "1.24.0", ""},
		{"http-apache", model.FingerprintInput{IP: "1.1.1.3", Port: 80, Banner: "Server: Apache/2.4.57 (Ubuntu)"}, "http", "Apache httpd", "2.4.57", "Ubuntu"},
		{"http-jetty", model.FingerprintInput{IP: "1.1.1.4", Port: 8080, Banner: "Server: Jetty(9.4.50.v20221201)"}, "http", "Jetty", "9.4.50.v20221201", ""},
		{"mysql", model.FingerprintInput{IP: "1.1.1.5", Port: 3306, Banner: "8.0.36-0ubuntu0.22.04.1"}, "mysql", "MySQL", "8.0.36", "Ubuntu"},
		{"redis-info", model.FingerprintInput{IP: "1.1.1.6", Port: 6379, Banner: "# Server\r\nredis_version:7.2.4"}, "redis", "Redis", "7.2.4", ""},
		{"redis-noauth", model.FingerprintInput{IP: "1.1.1.7", Port: 6379, Banner: "-NOAUTH Authentication required."}, "redis", "Redis", "", ""},
		{"ftp-vsftpd", model.FingerprintInput{IP: "1.1.1.8", Port: 21, Banner: "220 (vsFTPd 3.0.5)"}, "ftp", "vsFTPd", "3.0.5", ""},
		{"ftp-proftpd", model.FingerprintInput{IP: "1.1.1.9", Port: 21, Banner: "220 ProFTPD 1.3.8 Server (Debian)"}, "ftp", "ProFTPD", "1.3.8", "Debian"},
		{"unknown", model.FingerprintInput{IP: "2.2.2.2", Port: 9999, Banner: "some totally unknown service"}, "unknown", "", "", ""},
		{"empty-banner", model.FingerprintInput{IP: "2.2.2.3", Port: 9999, Banner: ""}, "unknown", "", "", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := svc.Identify(c.in)
			if got.Protocol != c.proto || got.Product != c.product || got.Version != c.version || got.OSHint != c.os {
				t.Errorf("识别结果不符:\n got  %+v\n want proto=%s product=%s version=%s os=%s",
					got, c.proto, c.product, c.version, c.os)
			}
			if c.proto == "unknown" && got.Confidence != 0 {
				t.Errorf("unknown 结果的 confidence 应为 0, got %v", got.Confidence)
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
