# stub-gateway-core.ps1 - 演练用 gateway-core 打桩（返回 HMAC 签名的默认路由表）
#
# 用途：门禁 #5「core 故障降级演练」的**决定性观测点**——让 wasm 插件真的拉到一张
# 合法（或故意坏签名）的路由表，从而可观测：
#   - 坏签名表 ⇒ 应被拒绝、缓存不写入（§6 第 8 行）
#   - 好签名表 ⇒ 写入缓存 ⇒ 后续请求命中 L2 ⇒ otpmask_route_degraded_total 增长（§6 第 3 行）
#
# 实现：System.Net.Sockets.TcpListener 手写最小 HTTP/1.1 响应（避免 HttpListener 的 URL ACL
# 管理员要求）；仅处理 GET /routes。
#
# 签名口径必须与两端一致（routecache.RouteTable.canon / gateway-core CanonicalBytes）：
#   规范字节 = {"version":V,"updated_at":T,"routes":[{tenant,model,default_engine[,fallback_engine][,target]}]}
#   （字段顺序与 Go struct 一致；fallback_engine/target 为空则省略 = omitempty）
#   签名 = HMAC-SHA256(K_rx, 规范字节)，以 base64（Go []byte 的 JSON 形式，带填充）输出。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\stub-gateway-core.ps1                 # 好签名
#   powershell -ExecutionPolicy Bypass -File scripts\stub-gateway-core.ps1 -BadSignature    # 坏签名
# 注：UTF-8 with BOM。

param(
    [int]$Port = 18085,
    [string]$KeyHex = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    [switch]$BadSignature,
    [string]$Tenant = 'tenant-a',
    [string]$Model = 'qwen-plus',
    [string]$DefaultEngine = 'cmaas',
    [string]$Target = 'https://cmaas.local',
    [int]$Version = 1
)

$ErrorActionPreference = 'Stop'

# ---- 规范字节（与 Go 端 canon 逐字节对齐）----
$updatedAt = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()  # 必须为整数（Go 端 int64 反序列化）
$routeCanon = '{"tenant":"' + $Tenant + '","model":"' + $Model + '","default_engine":"' + $DefaultEngine + '"'
if ($Target) { $routeCanon += ',"target":"' + $Target + '"' }
$routeCanon += '}'
$canon = '{"version":' + $Version + ',"updated_at":' + $updatedAt + ',"routes":[' + $routeCanon + ']}'

$key = [byte[]] -split ($KeyHex -replace '..', '0x$& ')
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $key
$sigBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canon))
if ($BadSignature) { $sigBytes[0] = $sigBytes[0] -bxor 0xFF } # 故意破坏签名
$sigB64 = [Convert]::ToBase64String($sigBytes)

$body = '{"version":' + $Version + ',"updated_at":' + $updatedAt + ',"routes":[' + $routeCanon + '],"signature":"' + $sigB64 + '"}'
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)

Write-Output ("[stub] listening :" + $Port + "  bad_signature=" + [bool]$BadSignature + "  version=" + $Version)
Write-Output ("[stub] canon = " + $canon)

$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
$listener.Start()
try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $stream.ReadTimeout = 3000
            $buf = New-Object byte[] 2048
            $n = 0
            try { $n = $stream.Read($buf, 0, $buf.Length) } catch { }
            $req = ''
            if ($n -gt 0) { $req = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n) }
            $firstLine = ($req -split "`r`n")[0]
            Write-Output ("[stub] " + (Get-Date -Format HH:mm:ss) + " <- " + $firstLine)

            $header = "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: " + $bodyBytes.Length + "`r`nConnection: close`r`n`r`n"
            $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
            $stream.Write($headerBytes, 0, $headerBytes.Length)
            $stream.Write($bodyBytes, 0, $bodyBytes.Length)
            $stream.Flush()
        } catch {
            Write-Output ("[stub] 处理异常: " + $_.Exception.Message)
        } finally {
            $client.Close()
        }
    }
} finally {
    $listener.Stop()
}
