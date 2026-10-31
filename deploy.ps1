[CmdletBinding()]
param(
    [string]$RemoteHost = '49.232.129.114',
    [string]$IdentityFile = "$env:USERPROFILE\.ssh\keychain_deploy_ed25519"
)
$ErrorActionPreference = 'Stop'
$bundle = $null
Push-Location $PSScriptRoot
try {
    if (git status --porcelain) { throw 'Commit all changes before deployment.' }
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    $bundle = Join-Path ([IO.Path]::GetTempPath()) ('study-flow-' + [guid]::NewGuid().ToString('N') + '.bundle')
    git bundle create $bundle main
    if ($LASTEXITCODE -ne 0) { throw 'Bundle creation failed.' }
    scp -i $IdentityFile -o IdentitiesOnly=yes -o BatchMode=yes $bundle "deploy@${RemoteHost}:/tmp/study-flow-main.bundle"
    if ($LASTEXITCODE -ne 0) { throw 'Bundle upload failed.' }
    ssh -i $IdentityFile -o IdentitiesOnly=yes -o BatchMode=yes "deploy@$RemoteHost" 'sudo -n /usr/local/sbin/deploy-project study-flow'
    if ($LASTEXITCODE -ne 0) { throw 'Deployment failed.' }
}
finally {
    if ($bundle -and (Test-Path -LiteralPath $bundle)) { Remove-Item -LiteralPath $bundle }
    Pop-Location
}
