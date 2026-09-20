import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


def run(c, cmd, timeout=30):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 从节点 port-forward tee-infer metrics
    print("=== tee-infer metrics (output guard) ===")
    rc, out, _ = run(c, "kubectl exec -n otpmask deploy/tee-infer-service -- wget -qO- http://127.0.0.1:19090/metrics 2>&1 | grep -E 'otpmask_output_guard' | head -30")
    print(out[:3000])

    # 再看输出侧审查有没有被触发——看请求计数
    print("\n=== 请求总计数 ===")
    rc, out, _ = run(c, "kubectl exec -n otpmask deploy/tee-infer-service -- wget -qO- http://127.0.0.1:19090/metrics 2>&1 | grep -E 'otpmask_output_guard_requests_total'")
    print(out)

    # 为什么没有触发？可能是 mock 引擎没有流式输出
    # 看 mock 引擎返回了什么——看总推理请求数
    print("\n=== 推理请求 ===")
    rc, out, _ = run(c, "kubectl exec -n otpmask deploy/tee-infer-service -- wget -qO- http://127.0.0.1:19090/metrics 2>&1 | grep -E 'otpmask_infer_requests_total' | head -5")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
