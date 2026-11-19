# Points System.Data.SQLite 2.x at Windows' own SQLite (winsqlite3.dll in System32) instead of e_sqlite3.dll.
#
# Why: locked-down machines (endpoint protection) refuse to load native DLLs from user-writable folders such as the
# user profile, so an e_sqlite3.dll shipped next to Vulnerator.exe cannot load there. winsqlite3.dll is part of Windows,
# signed by Microsoft, updated by Windows Update, and loads from System32. System.Data.SQLite fixes the native library
# name at "e_sqlite3"; this rewrites that one module reference in the built System.Data.SQLite.dll (Mono.Cecil).
# The build is 64-bit: 32-bit winsqlite3 uses the stdcall convention, System.Data.SQLite expects cdecl.
#
# Windows PowerShell 5.1. Usage: powershell -File tools\ci\Use-WindowsSqlite.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir)
$ErrorActionPreference = 'Stop'
trap {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    Write-Host ('::error::Use-WindowsSqlite: ' + $_.Exception.Message + ' / ' + $inner.GetType().FullName + ': ' + $inner.Message + ' at ' + $_.InvocationInfo.PositionMessage)
    exit 1
}

$binPath = (Resolve-Path $BinDir).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) 'vulnerator-cecil'
if (-not (Test-Path (Join-Path $work 'Mono.Cecil.0.11.6'))) {
    $out = & nuget install Mono.Cecil -Version 0.11.6 -OutputDirectory $work -NonInteractive 2>&1 | Out-String
    Write-Host $out
}
Add-Type -Path (Join-Path $work 'Mono.Cecil.0.11.6\lib\net40\Mono.Cecil.dll')

# Rewriting System.Data.SQLite invalidates its strong-name signature. DoD .NET hardening turns strong-name bypass off
# (AllowStrongNameBypass = 0), so a changed signed assembly is refused. The two SQLite assemblies are therefore made
# unsigned (with their InternalsVisibleTo entries and every reference to them updated), which loads under any setting.
$sqliteNames = @('System.Data.SQLite', 'System.Data.SQLite.EF6')
$emptyToken = New-Object byte[] 0

function Remove-StrongName($assembly) {
    $assembly.Name.PublicKey = $emptyToken
    $assembly.Name.HasPublicKey = $false
    $assembly.MainModule.Attributes = $assembly.MainModule.Attributes -band (-bnot [Mono.Cecil.ModuleAttributes]::StrongNameSigned)
    foreach ($attribute in @($assembly.CustomAttributes | Where-Object { $_.AttributeType.Name -eq 'InternalsVisibleToAttribute' })) {
        $value = [string]$attribute.ConstructorArguments[0].Value
        $friend = $value.Split(',')[0].Trim()
        $attribute.ConstructorArguments[0] = New-Object Mono.Cecil.CustomAttributeArgument($attribute.ConstructorArguments[0].Type, $friend)
    }
}

function Update-References($assembly) {
    $count = 0
    foreach ($reference in $assembly.MainModule.AssemblyReferences) {
        if ($sqliteNames -contains $reference.Name) {
            $reference.PublicKeyToken = $emptyToken
            $count++
        }
    }
    return $count
}

$readerParameters = New-Object Mono.Cecil.ReaderParameters
$readerParameters.ReadWrite = $true
$resolver = New-Object Mono.Cecil.DefaultAssemblyResolver
$resolver.AddSearchDirectory($binPath)
$readerParameters.AssemblyResolver = $resolver

# 1. System.Data.SQLite: native library -> winsqlite3, unsigned.
$assembly = [Mono.Cecil.AssemblyDefinition]::ReadAssembly((Join-Path $binPath 'System.Data.SQLite.dll'), $readerParameters)
try {
    $changed = 0
    foreach ($moduleReference in $assembly.MainModule.ModuleReferences) {
        if ($moduleReference.Name -eq 'e_sqlite3' -or $moduleReference.Name -eq 'e_sqlite3.dll') {
            $moduleReference.Name = 'winsqlite3'
            $changed++
        }
    }
    $names = @($assembly.MainModule.ModuleReferences | ForEach-Object { $_.Name }) -join ', '
    if ($changed -eq 0 -and $names -notmatch 'winsqlite3') { throw "System.Data.SQLite.dll has no e_sqlite3 module reference (references: $names)" }
    Remove-StrongName $assembly
    $assembly.Write()
    Write-Host "System.Data.SQLite.dll: native library winsqlite3 (module references: $names); unsigned."
}
finally { $assembly.Dispose() }

# 2. Every other program assembly that references the SQLite assemblies: point at the unsigned copies.
foreach ($file in @(Get-ChildItem $binPath -File | Where-Object { $_.Extension -in '.dll', '.exe' -and $_.Name -ne 'System.Data.SQLite.dll' })) {
    try { $assembly = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($file.FullName, $readerParameters) }
    catch { continue } # not a .NET assembly
    try {
        $references = Update-References $assembly
        $isSqlite = $sqliteNames -contains $assembly.Name.Name
        if ($references -eq 0 -and -not $isSqlite) { continue }
        if ($isSqlite -or $assembly.Name.HasPublicKey) {
            if (-not $isSqlite -and $file.Name -ne 'Vulnerator.exe') { throw "$($file.Name) is strong-named and references System.Data.SQLite; it cannot be updated" }
            Remove-StrongName $assembly
        }
        $assembly.Write()
        Write-Host "$($file.Name): $references reference(s) updated$(if ($isSqlite) { '; unsigned' })."
    }
    finally { $assembly.Dispose() }
}

# 3. The binding redirect for System.Data.SQLite names its public key token; drop it (unsigned assemblies bind by name).
$config = Join-Path $binPath 'Vulnerator.exe.config'
[xml]$xml = Get-Content $config -Raw
$ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$ns.AddNamespace('b', 'urn:schemas-microsoft-com:asm.v1')
foreach ($node in @($xml.SelectNodes("//b:dependentAssembly[b:assemblyIdentity[@name='System.Data.SQLite' or @name='System.Data.SQLite.EF6']]", $ns))) {
    [void]$node.ParentNode.RemoveChild($node)
    Write-Host 'Vulnerator.exe.config: System.Data.SQLite binding redirect removed.'
}
$xml.Save($config)

foreach ($stray in 'e_sqlite3.dll', 'SQLite.Interop.dll', 'sqlite3.dll') {
    Get-ChildItem $binPath -Recurse -Filter $stray | Remove-Item -Force
}
