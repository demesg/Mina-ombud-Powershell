#https://github.com/anthonyg-1/PSJsonWebToken
#Install-Module -Name PSJsonWebToken -Repository PSGallery -Scope CurrentUser
#Import-Module PSJsonWebToken
# $JSONWebKeySetEndpoint= "https://loginsandbox.havochvatten.se/nidp/oauth/nam/keys"
# $pubkey = (Invoke-RestMethod $JSONWebKeySetEndpoint).keys

# $Priv=get-content "C:\Magnus\hav_idp_sandbox.pkcs8"
# $privkey = $Priv | Select -Skip 1 | Select -SkipLast 1

if (Get-Module -ListAvailable -Name JWT) {
    Import-Module JWT
} else {
    Write-Host "Module does not exist, run as Admin to install."
    Install-Module JWT
}

$cert = Get-PfxCertificate -FilePath "C:\Magnus\hav_idp_sandbox_exportedCert.pfx" -Password (ConvertTo-SecureString "123456" -AsPlainText -Force)

## Teknisk guide Mina ombud: Avsnitt 4.1 Access tokens
## MUST: Client Credentials, Authorization: Bearer
## MUST: X-Service-Name ([a-zA-Z0-9-]) ?
$access_token=Invoke-RestMethod https://auth-accept.minaombud.se/auth/realms/dfm/protocol/openid-connect/token -Method POST -Body @{grant_type="client_credentials";client_id="Havochvatten-test";client_secret="66a1ba35-b195-4022-b369-fb365dc6d17c"; scope="user:self"} | Select-Object -ExpandProperty access_token

$decoded_token = $access_token | ConvertFrom-EncodedJsonWebToken
$Header=$decoded_token.Header|ConvertFrom-Json
$Payload=$decoded_token.Payload|ConvertFrom-Json
$Signature=$decoded_token.Signature


$now = Get-Date
write-host "access_token expire at: $($now.AddSeconds($(($Payload.exp)-($Payload.iat))))"

if ($($now.AddSeconds($(($Payload.exp)-($Payload.iat)))) -gt $now){

    $BeriYlles=(@{
        tredjeman= "2120000829";
        "fullmaktshavare"= @{id= "198602262381"; typ= "pnr"};
        fullmaktsgivarroll= "[ORGANISATION]";
        page= @{page= 0; size= 100}
        }
    )

    $idtoken= (@{
        "header"=@{
         alg="RS256";
         typ= "JWT"
        }
         "payload"=@{
         sub="95c72b50-ae52-4000-868f-521ec6a75b42";
         iss="$($Payload.iss)";
         aud="[$($Payload.aud)]";
         name="Beri Ylles";
         given_name="Beri";
         family_name="Ylles";
         "https://claims.oidc.se/1.0/personalNumber"="$($BeriYlles.fullmaktshavare.id)"
        }
        })

    (@{fullmaktshavare=@{id="198101052382";typ="pnr"};tredjeman="2120000829"})

    $jwt = New-Jwt -Cert $Cert -Header $($idtoken.header|ConvertTo-Json) -PayloadJson $($idtoken.payload|ConvertTo-Json) -Verbose
    write-host "Checking signing of JWT: $($jwt  |Test-Jwt -Cert $cert)"

    Invoke-RestMethod https://fullmakt-test.minaombud.se/dfm/formedlare/v1/sok/behorigheter -Method POST -ContentType "application/json" -Headers @{Authorization="Bearer $token"; 'X-Service-Name'='hav-testapp'; 'X-Id-Token'=$idtoken} -Body ($BeriYlles | ConvertTo-Json)

   
} else {
    write-host "access_token has expired"-ForegroundColor Red

}