# 还原 postgres.py：当前文本 = [936 解码](原始 UTF-8 字节) 之后又按 UTF-8 写出。
# 逆向：用 .NET 的 936 编码器把文本编回字节，再按 UTF-8 解码。
$ErrorActionPreference = 'Stop'
$p = 'D:\Hive\backend\core\storage\postgres.py'
$gbk = [System.Text.Encoding]::GetEncoding(936)
$utf8 = New-Object System.Text.UTF8Encoding($false)

$text = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
Write-Host "读入字符数: $($text.Length)"
if ($text[0] -eq [char]0xFEFF) {
    Write-Host "去掉开头 BOM"
    $text = $text.Substring(1)
}

# 有没有编不回 936 的字符？（有 = 原始字节已经丢了）
$lost = @()
for ($i = 0; $i -lt $text.Length; $i++) {
    $s = [string]$text[$i]
    try { $null = $gbk.GetBytes($s) } catch { $lost += ,@($i, [int]$text[$i]) }
}
Write-Host "编不回 936 的字符数: $($lost.Count)"
if ($lost.Count -gt 0) { $lost | Select-Object -First 8 | ForEach-Object { Write-Host "  pos=$($_[0]) U+$('{0:X4}' -f $_[1])" } }

$bytes = $gbk.GetBytes($text)
$original = [System.Text.Encoding]::UTF8.GetString($bytes)
$replacement = [char]0xFFFD
Write-Host "还原后是否含替换字符: $($original.Contains($replacement))"
foreach ($probe in @('四个资产各自怎么说', '为什么原来的写法是错的', '任务详情页', '回填到对应端口行', '删扫描')) {
    Write-Host "  含 '$probe': $($original.Contains($probe))"
}
if ($lost.Count -eq 0 -and -not $original.Contains($replacement)) {
    [System.IO.File]::WriteAllText($p, $original, $utf8)
    Write-Host "已写回（UTF-8 无 BOM）"
} else {
    Write-Host "有丢失字符，未写回 —— 需要人工处理"
}
