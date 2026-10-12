// Package repository 负责规则数据的加载与解析（数据访问层）。
// 识别规则存放在独立配置文件 rules.yaml 中，与程序代码解耦。
package repository

import (
	"fmt"
	"os"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"

	"banner-fingerprint/internal/model"
)

// CompiledRule 是编译好正则的识别规则。
type CompiledRule struct {
	model.Rule
	Patterns []*regexp.Regexp
}

// CompiledOSHint 是编译好正则的 OS 特征。
type CompiledOSHint struct {
	Regex *regexp.Regexp
	OS    string
}

// Repository 持有编译后的全部规则与 OS 特征。
type Repository struct {
	Rules   []CompiledRule
	OSHints []CompiledOSHint
}

// Load 从指定路径加载并编译规则文件。
// 某条规则/特征的正则编译失败时只告警并跳过，绝不让服务因配置问题崩溃。
func Load(path string) (*Repository, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %w", err)
	}

	var rs model.RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("解析规则文件失败: %w", err)
	}

	repo := &Repository{}

	for _, r := range rs.Rules {
		cr := CompiledRule{Rule: r}
		ok := true
		for _, p := range r.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[warn] 规则 %q 的正则编译失败: %v\n", r.ID, err)
				ok = false
				break
			}
			cr.Patterns = append(cr.Patterns, re)
		}
		if ok && len(cr.Patterns) > 0 {
			repo.Rules = append(repo.Rules, cr)
		}
	}

	// 按 priority 降序排序，保证更精确的规则先被尝试。
	sort.SliceStable(repo.Rules, func(i, j int) bool {
		return repo.Rules[i].Priority > repo.Rules[j].Priority
	})

	for _, h := range rs.OSHints {
		re, err := regexp.Compile(h.Regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[warn] OS 特征正则编译失败: %v\n", err)
			continue
		}
		repo.OSHints = append(repo.OSHints, CompiledOSHint{Regex: re, OS: h.OS})
	}

	return repo, nil
}
