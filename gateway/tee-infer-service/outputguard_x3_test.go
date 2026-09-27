package main

// X-3（G23）配额回冲规则单测。
//
// 口径①（与 GA-计费 P0-3 故障口径对齐）：
//   - 全拦（零下发）：全额回冲输入预占（TokensIn 净额归 0、窗口额度释放），
//     计 deny、RefundedTokensIn 留痕、不出 infer 账（from/to 该租户零增量）。
//   - 部分截断（有下发）：输入保留，输出仅按实际下发计费，infer 事件 result=content_filter。
//
// 非空转：partial 用例以 checkDeliveredFrames 验证被拦句确实未随帧下发。
import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/protocol/go"
)

// x3ScriptL2 按文本内容判定的 L2：含违规标记的句子 block，其余放行
// （内容判定，不受级联多次调用/缓冲影响）。
type x3ScriptL2 struct{}

func (x3ScriptL2) Classify(text string) (string, float64, string) {
	if strings.Contains(text, "违规内容") {
		return "A1-06", 0.9, "违规内容"
	}
	return "", 0, ""
}

// x3DoRequest 发起一次流式 text infer，返回已下发帧。
func x3DoRequest(t *testing.T, ts *httptest.Server, text string) []deliveredFrame {
	t.Helper()
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, text,
		protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("拦截体现在终止码，HTTP 应 200，got %d", resp.StatusCode)
	}
	return parseWireFrames(t, mustReadAll(t, resp.Body), sessionID, kenc)
}

func TestX3FullBlockRefund(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.outputGuardMode = outputGuardEnforcing
	srv.outputGuardParams = defaultOutputGuardParams()
	srv.outputGuardCascade = cascadeParams(true)
	srv.outputGuardL2 = fakeL2Classifier{cat: "A1-06", conf: 0.9}
	srv.model = framewiseStubEngine{deltas: []string{"第一句。", "第二句。"}}
	// 窗口配额（证明回冲同步释放窗口额度）
	srv.quota = map[string]quotaSpec{defaultTenant: {
		Limits: []quotaLimit{{Window: quotaWindowMinute, MaxTokens: 1000}},
	}}

	const userText = "请讲个笑话"
	wantIn := srv.countTokens(userText)
	frames := x3DoRequest(t, ts, userText)

	// 整流：零 delta 下发 + content_filter
	for i, f := range frames {
		if f.Delta != "" {
			t.Fatalf("全拦不得下发 delta（帧 %d 泄漏 %q）", i, f.Delta)
		}
	}
	if last := frames[len(frames)-1]; last.Finish != "content_filter" {
		t.Fatalf("终止码应 content_filter，实际 %q", last.Finish)
	}

	rec := srv.usage[defaultTenant]
	if rec == nil {
		t.Fatal("应有 usage 记录")
	}
	if rec.TokensIn != 0 || rec.TokensOut != 0 || rec.Requests != 0 {
		t.Fatalf("全拦净额应归零，实际 in=%d out=%d req=%d", rec.TokensIn, rec.TokensOut, rec.Requests)
	}
	if rec.Denies != 1 {
		t.Fatalf("全拦应计 1 deny，实际 %d", rec.Denies)
	}
	if rec.RefundedTokensIn != wantIn {
		t.Fatalf("回冲留痕期望 %d，实际 %d", wantIn, rec.RefundedTokensIn)
	}
	// 窗口额度已释放
	if used := srv.quotaWindowUsed(defaultTenant); used != 0 {
		t.Fatalf("全拦后窗口已用应为 0，实际 %d", used)
	}
	if ok, _ := srv.reserveQuota(defaultTenant, 1000); !ok {
		t.Fatal("回冲后应能再占满窗口额度（释放验证失败）")
	}
	// 计费 from/to：该租户零增量（全拦无 infer 事件）
	to := time.Now().Add(time.Hour).UnixNano()
	inc := aggregateUsage(srv.audit.query(""), 0, to)[defaultTenant]
	if inc != nil && (inc.TokensIn != 0 || inc.TokensOut != 0 || inc.Requests != 0) {
		t.Fatalf("全拦计费增量应为空/零，实际 %+v", inc)
	}
	if n := srv.audit.countByAction("output_blocked"); n != 1 {
		t.Fatalf("应落 1 条 output_blocked，实际 %d", n)
	}
}

func TestX3PartialTruncationBillsDelivered(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.outputGuardMode = outputGuardEnforcing
	srv.outputGuardParams = defaultOutputGuardParams()
	srv.outputGuardCascade = cascadeParams(true)
	srv.outputGuardL2 = x3ScriptL2{}
	const safeSentence = "这是安全的第一句。"
	const badSentence = "这是违规内容第二句。"
	srv.model = framewiseStubEngine{deltas: []string{safeSentence, badSentence}}

	const userText = "请讲个笑话"
	wantIn := srv.countTokens(userText)
	wantDelivered := srv.countTokens(safeSentence)
	frames := x3DoRequest(t, ts, userText)

	// 非空转：被拦句不得随帧下发；实际仅下发安全句；终止码 content_filter
	if vs := checkDeliveredFrames(frames, frameCheckOpts{
		Forbidden: []string{"违规内容"}, WantFinish: "content_filter",
	}); len(vs) != 0 {
		t.Fatalf("被拦内容零泄漏且 content_filter，断言违规=%+v", vs)
	}
	var delivered strings.Builder
	for _, f := range frames {
		delivered.WriteString(f.Delta)
	}
	if delivered.String() != safeSentence {
		t.Fatalf("仅应下发安全句，实际 %q", delivered.String())
	}

	rec := srv.usage[defaultTenant]
	if rec == nil {
		t.Fatal("应有 usage 记录")
	}
	// 输入保留、输出仅按下发、计成功请求、无回冲留痕
	if rec.TokensIn != wantIn {
		t.Fatalf("部分截断输入应保留=%d，实际 %d", wantIn, rec.TokensIn)
	}
	if rec.TokensOut != wantDelivered {
		t.Fatalf("输出应仅按下发=%d，实际 %d", wantDelivered, rec.TokensOut)
	}
	if rec.Requests != 1 || rec.Denies != 0 || rec.RefundedTokensIn != 0 {
		t.Fatalf("应计 1 成功请求且无回冲，实际 req=%d denies=%d refund=%d",
			rec.Requests, rec.Denies, rec.RefundedTokensIn)
	}
	// 计费 from/to：in=保留输入，out=仅下发，1 个请求
	to := time.Now().Add(time.Hour).UnixNano()
	inc := aggregateUsage(srv.audit.query(""), 0, to)[defaultTenant]
	if inc == nil || inc.TokensIn != wantIn || inc.TokensOut != wantDelivered || inc.Requests != 1 {
		t.Fatalf("计费增量期望 in=%d out=%d req=1，实际 %+v", wantIn, wantDelivered, inc)
	}
	// infer 事件合同：result=content_filter
	found := false
	for _, e := range srv.audit.query("") {
		if e.Action == "infer" && e.Result == "content_filter" {
			found = true
		}
	}
	if !found {
		t.Fatal("应存在 result=content_filter 的 infer 事件")
	}
}
