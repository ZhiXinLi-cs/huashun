// client 是 Banner 指纹识别客户端：读取本地 JSON 文件、发往 server、展示识别结果。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"banner-fingerprint/internal/model"
)

func main() {
	file := os.Getenv("CLIENT_FILE")
	if file == "" {
		file = "data/samples.json"
	}
	serverURL := os.Getenv("SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	inputs, err := readInputs(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	results, err := sendToServer(serverURL, inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	printResults(results)
}

func readInputs(path string) ([]model.FingerprintInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取输入文件失败: %w", err)
	}
	var inputs []model.FingerprintInput
	if err := json.Unmarshal(data, &inputs); err != nil {
		return nil, fmt.Errorf("解析输入 JSON 失败（应为数组）: %w", err)
	}
	return inputs, nil
}

func sendToServer(serverURL string, inputs []model.FingerprintInput) ([]model.FingerprintResult, error) {
	body, _ := json.Marshal(inputs)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(serverURL+"/fingerprint", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("请求 server 失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server 返回错误 %d: %s", resp.StatusCode, respBody)
	}

	var results []model.FingerprintResult
	if err := json.Unmarshal(respBody, &results); err != nil {
		return nil, fmt.Errorf("解析 server 响应失败: %w", err)
	}
	return results, nil
}

func printResults(results []model.FingerprintResult) {
	fmt.Printf("%-16s %-6s %-9s %-15s %-14s %-9s %s\n",
		"IP", "PORT", "PROTOCOL", "PRODUCT", "VERSION", "OS_HINT", "CONF")
	for _, r := range results {
		fmt.Printf("%-16s %-6d %-9s %-15s %-14s %-9s %.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
}
