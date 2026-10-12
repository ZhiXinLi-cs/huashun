// Package service 承载指纹识别的核心业务逻辑（识别引擎）。
package service

import (
	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/repository"
)

// Service 是 Banner 指纹识别引擎。
type Service struct {
	repo *repository.Repository
}

// New 构造识别引擎。
func New(repo *repository.Repository) *Service {
	return &Service{repo: repo}
}

// Identify 识别单条 banner。绝不 panic，认不出时返回 protocol:"unknown"。
func (s *Service) Identify(in model.FingerprintInput) model.FingerprintResult {
	res := model.FingerprintResult{
		IP:         in.IP,
		Port:       in.Port,
		Protocol:   "unknown",
		Confidence: 0,
	}

	banner := in.Banner
	if banner == "" {
		return res
	}

	// 规则已按 priority 降序排列，首个命中即返回。
	for _, rule := range s.repo.Rules {
		for _, re := range rule.Patterns {
			m := re.FindStringSubmatch(banner)
			if m == nil {
				continue
			}
			res.Protocol = rule.Protocol
			res.Product = rule.Product
			res.Confidence = rule.Confidence
			// 捕获组 1 作为版本号（规则未定义捕获组时置空）。
			if len(m) > 1 && m[1] != "" {
				res.Version = m[1]
			}
			res.OSHint = s.detectOS(banner)
			return res
		}
	}
	return res
}

// IdentifyAll 批量识别，返回与输入顺序一致的结果。
func (s *Service) IdentifyAll(inputs []model.FingerprintInput) []model.FingerprintResult {
	results := make([]model.FingerprintResult, 0, len(inputs))
	for _, in := range inputs {
		results = append(results, s.Identify(in))
	}
	return results
}

// detectOS 用全局 OS 特征正则扫描 banner，命中即返回对应的操作系统名。
func (s *Service) detectOS(banner string) string {
	for _, h := range s.repo.OSHints {
		if h.Regex.MatchString(banner) {
			return h.OS
		}
	}
	return ""
}
