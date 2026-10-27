# Draws the app icon (indigo-to-sky shield with a white check) at every Windows icon size and
# writes app\app.ico (PNG-compressed entries) and app\logo-256.png. No downloads.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File app\Make-Icon.ps1
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$dir = $PSScriptRoot

function New-Shield([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 256.0
    function P([double]$x, [double]$y) { New-Object System.Drawing.PointF([float]($x * $s), [float]($y * $s)) }

    # shield: flat top corners, curved sides meeting in a point at the bottom
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddLine((P 128 14), (P 226 50))
    $path.AddLine((P 226 50), (P 226 122))
    $path.AddBezier((P 226 122), (P 226 184), (P 186 228), (P 128 246))
    $path.AddBezier((P 128 246), (P 70 228), (P 30 184), (P 30 122))
    $path.AddLine((P 30 122), (P 30 50))
    $path.CloseFigure()

    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush((P 30 14), (P 226 246),
        [System.Drawing.Color]::FromArgb(255, 79, 70, 229), [System.Drawing.Color]::FromArgb(255, 14, 165, 233))
    $g.FillPath($brush, $path)

    # subtle top highlight; the gradient spans the whole shield because GDI+ repeats it past its end
    $hl = New-Object System.Drawing.Drawing2D.LinearGradientBrush((P 0 13), (P 0 247),
        [System.Drawing.Color]::FromArgb(70, 255, 255, 255), [System.Drawing.Color]::FromArgb(0, 255, 255, 255))
    $g.FillPath($hl, $path)

    # check mark, thicker at small sizes so it stays readable
    $w = if ($size -le 24) { 30 } elseif ($size -le 48) { 26 } else { 22 }
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [float]($w * $s))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $g.DrawLines($pen, [System.Drawing.PointF[]]@((P 82 132), (P 114 164), (P 176 100)))

    $g.Dispose()
    return $bmp
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$pngs = @()
foreach ($sz in $sizes) {
    $bmp = New-Shield $sz
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    if ($sz -eq 256) { $bmp.Save((Join-Path $dir 'logo-256.png'), [System.Drawing.Imaging.ImageFormat]::Png) }
    $bmp.Dispose()
    $pngs += , $ms.ToArray()
}

# ICO: 6-byte header, 16-byte directory entry per image, then the PNG data
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]
    $dim = if ($sz -ge 256) { 0 } else { $sz }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]$pngs[$i].Length); $bw.Write([UInt32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $bw.Write($p) }
$bw.Flush()
[System.IO.File]::WriteAllBytes((Join-Path $dir 'app.ico'), $out.ToArray())
Write-Output "wrote $(Join-Path $dir 'app.ico') ($($sizes.Count) sizes) and logo-256.png"
