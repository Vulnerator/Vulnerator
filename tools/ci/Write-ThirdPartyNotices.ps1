# Writes LICENSE.txt and THIRD-PARTY-NOTICES.txt next to Vulnerator.exe.
# The notices are generated from the NuGet packages the build restored (packages.config + each package's .nuspec and
# license files), so they always match what ships. Development-only packages (Fody weavers) are left out.
#
# Windows PowerShell 5.1. Pure ASCII.
# Usage: powershell -File tools\ci\Write-ThirdPartyNotices.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir)
$ErrorActionPreference = 'Stop'

$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$bin = (Resolve-Path $BinDir).Path
$packagesDir = Join-Path $root 'packages'
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $bin 'LICENSE.txt') -Force

$builder = New-Object System.Text.StringBuilder
[void]$builder.AppendLine('Vulnerator 2.0 - third-party notices')
[void]$builder.AppendLine('====================================')
[void]$builder.AppendLine('')
[void]$builder.AppendLine('Vulnerator 2.0 is distributed under the MIT License (LICENSE.txt). It includes the components below, each')
[void]$builder.AppendLine('under its own license. The database engine is winsqlite3.dll, part of Windows; it is not distributed with')
[void]$builder.AppendLine('Vulnerator. Icons: Material Design Icons (Pictogrammers) through MahApps.Metro.IconPacks.')
[void]$builder.AppendLine('')

[xml]$config = Get-Content (Join-Path $root 'packages.config')
$missing = @()
foreach ($package in ($config.packages.package | Sort-Object id)) {
    if ($package.developmentDependency -eq 'true') { continue }
    $folder = Join-Path $packagesDir ($package.id + '.' + $package.version)
    if (-not (Test-Path $folder)) { $missing += $package.id; continue }
    $nuspecPath = Get-ChildItem $folder -Filter '*.nuspec' | Select-Object -First 1
    $metadata = $null
    if ($null -ne $nuspecPath) { $metadata = ([xml](Get-Content $nuspecPath.FullName -Raw)).package.metadata }

    [void]$builder.AppendLine('------------------------------------------------------------------------------')
    [void]$builder.AppendLine($package.id + ' ' + $package.version)
    if ($null -ne $metadata) {
        if ($metadata.authors) { [void]$builder.AppendLine('Authors: ' + $metadata.authors) }
        if ($metadata.copyright) { [void]$builder.AppendLine('Copyright: ' + $metadata.copyright) }
        if ($metadata.projectUrl) { [void]$builder.AppendLine('Project: ' + $metadata.projectUrl) }
        $license = $metadata.license
        if ($license -is [System.Xml.XmlElement]) {
            $type = $license.GetAttribute('type')
            if ($type -eq 'expression') { [void]$builder.AppendLine('License: ' + $license.InnerText) }
        }
        if ($metadata.licenseUrl) { [void]$builder.AppendLine('License URL: ' + $metadata.licenseUrl) }
    }
    # Full license texts shipped inside the package.
    $texts = Get-ChildItem $folder -Recurse -File | Where-Object { $_.Name -match '^(LICEN[CS]E|COPYING|NOTICE|ThirdPartyNotices)(\.(txt|md))?$' }
    foreach ($text in $texts) {
        [void]$builder.AppendLine('')
        [void]$builder.AppendLine('[' + $text.Name + ']')
        [void]$builder.AppendLine((Get-Content $text.FullName -Raw).Trim())
    }
    [void]$builder.AppendLine('')
}
if ($missing.Count -gt 0) {
    Write-Host ('::error::packages not restored, notices incomplete: ' + ($missing -join ', '))
    exit 1
}
[System.IO.File]::WriteAllText((Join-Path $bin 'THIRD-PARTY-NOTICES.txt'), $builder.ToString(), (New-Object System.Text.UTF8Encoding($false)))
$leftover = @(Get-ChildItem $bin -Recurse -File | Where-Object { $_.Name -eq 'MahApps.Metro.IconPacks.dll' })
if ($leftover.Count -gt 0) { Write-Host '::error::the old icon library (MahApps.Metro.IconPacks.dll) is still in the release folder'; exit 1 }
$noticeText = [System.IO.File]::ReadAllText((Join-Path $bin 'THIRD-PARTY-NOTICES.txt'))
$listed = ([regex]::Matches($noticeText, '(?m)^-{20,}')).Count
Write-Host ('::notice::THIRD-PARTY-NOTICES.txt: ' + $listed + ' components, ' + $noticeText.Length + ' characters; icon packs shipped: ' + ((Get-ChildItem $bin -Filter 'MahApps.Metro.IconPacks*.dll' | ForEach-Object { $_.Name }) -join ', '))
Write-Host ('Wrote LICENSE.txt and THIRD-PARTY-NOTICES.txt (' + @($config.packages.package).Count + ' packages listed in packages.config)')
