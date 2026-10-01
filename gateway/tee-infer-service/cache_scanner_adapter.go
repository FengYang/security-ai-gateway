package main

import (
	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
)

// l1CacheScanner 复用 outputguard 的 L1 分类器作为缓存读时快审扫描器（§7.2）。
// 适配器模式：将 OutputClassifier 包装为 cacheengine.FastScanner 接口。
//
// 设计要点：
//   - 零分配、低延迟（L1 是 AC 自动机，< 1ms/KB）
//   - 命中即 block（confidence > 0），action 由 cacheengine 配置决定
//   - 分类器不可用时返回 ErrClassifierUnavailable → cacheengine fail-closed
type l1CacheScanner struct {
	classifier OutputClassifier
}

// NewL1CacheScanner 构造基于 L1 的缓存快审扫描器。
// classifier 为 nil 时返回 nil（调用方应 fallback 到 stub）。
func NewL1CacheScanner(classifier OutputClassifier) cacheengine.FastScanner {
	if classifier == nil {
		return nil
	}
	return &l1CacheScanner{classifier: classifier}
}

// Scan 执行快审。
// 命中 → Allow=false，Reason=category，Match=命中片段
// 未命中 → Allow=true
func (s *l1CacheScanner) Scan(text string) (cacheengine.ScanVerdict, error) {
	if s.classifier == nil {
		return cacheengine.ScanVerdict{}, cacheengine.ErrClassifierUnavailable
	}

	category, confidence, match := s.classifier.Classify(text)
	if category != "" && confidence > 0 {
		return cacheengine.ScanVerdict{
			Allow:  false,
			Reason: category,
			Match:  match,
		}, nil
	}

	return cacheengine.ScanVerdict{Allow: true}, nil
}
