// Package model 定义指纹识别系统内各层共享的数据结构。
package model

// FingerprintInput 是 client 发往 server 的一条待识别原始数据。
type FingerprintInput struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// FingerprintResult 是一条原始数据对应的识别结果。
type FingerprintResult struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Rule 对应规则文件中一条「协议+软件」的识别规则。
type Rule struct {
	ID         string   `yaml:"id"`
	Protocol   string   `yaml:"protocol"`
	Product    string   `yaml:"product"`
	Priority   int      `yaml:"priority"`
	Confidence float64  `yaml:"confidence"`
	Patterns   []string `yaml:"patterns"`
}

// OSHint 对应规则文件中一条全局操作系统特征。
type OSHint struct {
	Regex string `yaml:"regex"`
	OS    string `yaml:"os"`
}

// RuleSet 是规则文件（rules.yaml）的顶层结构。
type RuleSet struct {
	OSHints []OSHint `yaml:"os_hints"`
	Rules   []Rule   `yaml:"rules"`
}
