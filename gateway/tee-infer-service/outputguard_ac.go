// 输出侧内容审查 — AC 自动机（Aho-Corasick），用于多模式子串匹配。
//
// 用途：词库 contains / variant 类型规则的批量匹配（§4.2.4）。
// 性能：预处理 O(Σ len(pattern))，单次匹配 O(len(text) + num_hits)。
//
// 实现要点：
//   - trie 节点用 slice 存子节点（rune → 下标），Go map 替代（实现简单）
//   - fail 链用 BFS 构建
//   - matchFirst 返回第一个命中（权重最高优先；M1 按顺序返回第一个）
//
// M1 实现 trade-off：
//   - 节点用 map[rune]int 存子节点（代码简洁，非性能最优）
//   - 命中返回第一个匹配（非权重最高；权重排序在 M2 优化）
//   - Unicode rune 级别匹配（不是 byte），天然支持中文
package main

import "fmt"

// acPattern AC 自动机模式（带规则元数据）。
type acPattern struct {
	text string     // 模式文本（归一化后的关键词）
	rule lexiconRule // 对应规则
}

// acNode AC 自动机节点。
type acNode struct {
	children map[rune]int // 子节点：rune → 节点下标
	fail     int          // fail 链目标节点下标
	output   int          // 终结模式下标（-1 表示非终结）；M1 每个节点最多一个模式
}

// acAutomaton AC 自动机。
type acAutomaton struct {
	nodes    []acNode    // 节点数组（下标 0 为根）
	patterns []acPattern // 模式列表（output 字段引用此列表下标）
}

// newACAutomaton 构建 AC 自动机。
func newACAutomaton(patterns []acPattern) *acAutomaton {
	ac := &acAutomaton{
		patterns: patterns,
		nodes:    []acNode{{children: make(map[rune]int), fail: 0, output: -1}},
	}

	// 1. 构建 trie
	for i, p := range patterns {
		ac.insert(p.text, i)
	}

	// 2. BFS 构建 fail 链
	ac.buildFail()

	return ac
}

// insert 插入一个模式到 trie。
func (ac *acAutomaton) insert(pattern string, patternIdx int) {
	cur := 0
	for _, r := range pattern {
		child, ok := ac.nodes[cur].children[r]
		if !ok {
			child = len(ac.nodes)
			ac.nodes = append(ac.nodes, acNode{children: make(map[rune]int), fail: 0, output: -1})
			ac.nodes[cur].children[r] = child
		}
		cur = child
	}
	// 终结节点记录模式下标（M1：后插入覆盖先插入；精确语义 M2 支持多模式同节点）
	ac.nodes[cur].output = patternIdx
}

// buildFail BFS 构建 fail 链。
func (ac *acAutomaton) buildFail() {
	var queue []int
	// 根的直接子节点 fail = 根，入队
	for _, child := range ac.nodes[0].children {
		ac.nodes[child].fail = 0
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]

		for r, v := range ac.nodes[u].children {
			// 找 v 的 fail 节点
			f := ac.nodes[u].fail
			for f != 0 {
				if _, ok := ac.nodes[f].children[r]; ok {
					break
				}
				f = ac.nodes[f].fail
			}
			if fc, ok := ac.nodes[f].children[r]; ok && fc != v {
				ac.nodes[v].fail = fc
			} else {
				ac.nodes[v].fail = 0
			}

			// 输出链优化：若 fail 节点有 output，则继承（M1 简化为直接使用，不做 output 链）
			// （匹配时沿 fail 链回溯检查 output）
			queue = append(queue, v)
		}
	}
}

// acHit AC 自动机命中结果。
type acHit struct {
	rule   lexiconRule // 命中的规则
	start  int         // 命中起始 rune 下标
	end    int         // 命中结束 rune 下标（不含）
}

// matchFirst 返回第一个命中（按文本中出现顺序）；无命中返回 nil。
// M1 简化：找到第一个即返回，不找全部、不比较权重。
func (ac *acAutomaton) matchFirst(text string) *acHit {
	cur := 0
	runes := []rune(text)
	for i, r := range runes {
		// 沿 fail 链回溯，直到找到能走的边或到根
		for cur != 0 {
			if _, ok := ac.nodes[cur].children[r]; ok {
				break
			}
			cur = ac.nodes[cur].fail
		}
		if next, ok := ac.nodes[cur].children[r]; ok {
			cur = next
		}
		// 沿 fail 链检查 output
		tmp := cur
		for tmp != 0 {
			if ac.nodes[tmp].output >= 0 {
				idx := ac.nodes[tmp].output
				p := ac.patterns[idx]
				start := i - len([]rune(p.text)) + 1
				return &acHit{rule: p.rule, start: start, end: i + 1}
			}
			tmp = ac.nodes[tmp].fail
		}
	}
	return nil
}

// patternCount 返回模式数量。
func (ac *acAutomaton) patternCount() int { return len(ac.patterns) }

// maxPatternLen 返回最长模式的 rune 数（用于派生 P-WINDOW-CHARS）。
func (ac *acAutomaton) maxPatternLen() int {
	max := 0
	for _, p := range ac.patterns {
		if n := len([]rune(p.text)); n > max {
			max = n
		}
	}
	return max
}

// nodeCount 返回节点数（测试/可观测用）。
func (ac *acAutomaton) nodeCount() int { return len(ac.nodes) }

// String 返回简要描述（调试用）。
func (ac *acAutomaton) String() string {
	return fmt.Sprintf("AC{patterns=%d, nodes=%d}", len(ac.patterns), len(ac.nodes))
}
