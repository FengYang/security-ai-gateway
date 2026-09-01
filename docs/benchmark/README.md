# R1-A 性能基准结果目录（GF.5）

本目录存放 R1-A 性能决策门的基准结果（真机就绪后采集）。

## 采集方式

场景矩阵已固化于 `scripts/perf-baseline.sh`（评审 P1-5，禁止临场增删）：

- **prompt**：short（≤100 token）/ long（≥2k token）
- **mode**：stream（SSE 流式）/ non-stream（单分片聚合）
- **concurrency**：16 / 64
- **chain**：enc（密态全链路）/ plain（明文基线直连引擎）

共 16 组场景；enc 与 plain 对照得出加密链开销，tee_gpu 与 cmaas 各跑一轮。

## 目录约定

```
docs/benchmark/
  r1a/                     # 一轮完整矩阵（或带日期：<date>-r1a）
    r1a-baseline.csv       # 汇总：tag,prompt,mode,concurrency,chain,rps,p50,p99
    raw/                   # 原始 wrk/ab 输出（逐场景一份）
  r1a-conclusion.md        # 决策结论（模板见下）
```

## 决策门（R1-A）

| 指标 | 阈值 | 判定 |
| --- | --- | --- |
| 密态吞吐开销（enc vs plain） | ≤ 35% | 超阈值 → 性能优化或路径重评 |
| P99 延迟劣化（enc vs plain） | ≤ +30% | 超阈值 → 性能优化或路径重评 |
| tee_gpu vs cmaas 吞吐/延迟 | 对比记录 | 决定生产主路径 |

## r1a-conclusion.md 模板

```markdown
# R1-A 性能决策结论（<日期>）
- 环境：集群基线（见 deploy/higress/README.md）、引擎版本、模型、Higress/Gateway 版本
- 结果：见 r1a-baseline.csv；关键数字（enc/plain 开销、P99 劣化）
- 判定：通过 / 不通过（对照决策门阈值）
- 结论：生产主路径 = tee_gpu / cmaas；后续动作
- 采集人 / 复核人 / 日期
```
