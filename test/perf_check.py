import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.31.168', username='root', password='yf0537', timeout=10)

# 检查压测工具
for tool in ['wrk', 'ab', 'hey', 'go', 'curl']:
    stdin, stdout, stderr = c.exec_command(f"which {tool} 2>&1; echo '---'")
    print(f"{tool}: {stdout.read().decode().strip().split(chr(10))[0]}")

# 看网关资源占用
gw_pod = "higress-gateway-dc6665557-xhhxc"
stdin, stdout, stderr = c.exec_command(
    f"kubectl top pod -n higress-system {gw_pod} 2>&1 || echo 'top not available'"
)
print(f"\n网关资源: {stdout.read().decode().strip()}")

# 看节点资源
stdin, stdout, stderr = c.exec_command("free -h 2>&1; echo '---'; nproc 2>&1")
print(f"\n节点资源:\n{stdout.read().decode()}")

c.close()
