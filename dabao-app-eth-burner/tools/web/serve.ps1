# Serves this folder on http://localhost:<port>/ so the page gets WebHID.
# Browsers only expose WebHID to pages loaded from https or from localhost, not from a file.
# Usage: pwsh -File serve.ps1 [-Port 8765]      (Ctrl+C stops it)
# Nothing to install; it listens on this computer only.
param([int]$Port = 8765)

$root = $PSScriptRoot
$types = @{ '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.css' = 'text/css; charset=utf-8'; '.png' = 'image/png'; '.svg' = 'image/svg+xml'; '.json' = 'application/json' }

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "Serving $root at http://localhost:$Port/  (Ctrl+C to stop)"
try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $rel = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath).TrimStart('/')
        if ($rel -eq '') { $rel = 'index.html' }
        $path = [IO.Path]::GetFullPath((Join-Path $root $rel))
        $inside = $path.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
        if ($inside -and (Test-Path $path -PathType Leaf)) {
            $bytes = [IO.File]::ReadAllBytes($path)
            $type = $types[[IO.Path]::GetExtension($path).ToLower()]
            $ctx.Response.ContentType = if ($type) { $type } else { 'application/octet-stream' }
            $ctx.Response.Headers['Cache-Control'] = 'no-store'
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else {
            $ctx.Response.StatusCode = 404
        }
        $ctx.Response.Close()
        Write-Host "$($ctx.Response.StatusCode) /$rel"
    }
} finally { $listener.Stop() }
