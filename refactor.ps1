$baseDir = "services\src\main\java"

Get-ChildItem -Path $baseDir -Recurse -Filter *.java | ForEach-Object {
    $file = $_.FullName
    $parentFolder = $_.Directory.Name
    $grandparentFolder = $_.Directory.Parent.Name
    
    $packageName = ""
    if ($grandparentFolder -eq "kerberos_core") {
        $packageName = "kerberos_core.$parentFolder"
    } else {
        $packageName = $parentFolder
    }

    $content = Get-Content $file -Raw

    $header = "package $packageName;`r`n"
    if ($packageName -ne "kerberos_core.models") {
        $header += "import kerberos_core.models.*;`r`n"
    }
    if ($packageName -ne "kerberos_core.crypto") {
        $header += "import kerberos_core.crypto.*;`r`n"
    }

    if (-not $content.StartsWith("package")) {
        $newContent = $header + $content
        Set-Content -Path $file -Value $newContent
    }
}
