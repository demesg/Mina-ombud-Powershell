if (Get-Module -ListAvailable -Name JWT) {
    Import-Module JWT
} else {
    Write-Host "Module does not exist, run as Admin to install."
    #https://github.com/SP3269/posh-jwt
    Install-Module JWT
}
$cert = Get-PfxCertificate -FilePath "C:\Magnus\hav_idp_sandbox_exportedCert.pfx" -Password (ConvertTo-SecureString "" -AsPlainText -Force)

$x5u= "https://loginsandbox.havochvatten.se/nidp/oauth/nam/keys"
$x5= Invoke-RestMethod $x5u -Method GET
Write-host "X.509 URL: + $x5u" -ForegroundColor White
Write-host "Response: " ($x5.keys|ConvertTo-Json) -ForegroundColor White
$client_id="Havochvatten-test"

## Teknisk guide Mina ombud: Avsnitt 4.1 Access tokens
## MUST: Client Credentials, Authorization: Bearer
## MUST: X-Service-Name ([a-zA-Z0-9-]) ?
$access_token=Invoke-RestMethod https://auth-accept.minaombud.se/auth/realms/dfm/protocol/openid-connect/token -Method POST -Body @{grant_type="client_credentials";client_id=$client_id;client_secret="66a1ba35-b195-4022-b369-fb365dc6d17c"; scope="user:self"} | Select-Object -ExpandProperty access_token

$Header=$access_token.split(".")[0]| ConvertFrom-Base64UrlString |ConvertFrom-Json
$Payload=$access_token.split(".")[1]| ConvertFrom-Base64UrlString |ConvertFrom-Json
$Signature=$access_token.split(".")[2]| ConvertFrom-Base64UrlString 

write-host "access_token: " + $access_token -ForegroundColor DarkGreen

$now = Get-Date
write-host "access_token expire at: $($now.AddSeconds($(($Payload.exp)-($Payload.iat))))" -ForegroundColor DarkGreen

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
         typ= "JWT";
         kid= "$(($x5.keys).kid)";
         x5u= "$x5u";
         x5t= "$(($x5.keys).x5t)";
        }
         "payload"=@{
         sub="95c72b50-ae52-4000-868f-521ec6a75b42";
         iss="$($Payload.iss)";
         aud="@($Payload.aud)";
         azp="$($client_id)"
         name="Beri Ylles";
         given_name="Beri";
         family_name="Ylles";
         "https://claims.oidc.se/1.0/personalNumber"="$($BeriYlles.fullmaktshavare.id)"
        }
        })

    #(@{fullmaktshavare=@{id="198101052382";typ="pnr"};tredjeman="2120000829"})


    Write-Host "'X-Id-Token'= $($idtoken|ConvertTo-Json)" -ForegroundColor DarkMagenta

    #Signera Header och Payload
    $jwt = New-Jwt -Cert $Cert -Header $($idtoken.header|ConvertTo-Json) -PayloadJson $($idtoken.payload|ConvertTo-Json)
    write-host "JWT: $jwt"

    write-host "Checking signing of JWT: $($jwt  |Test-Jwt -Cert $cert)"

    $behorigheter = Invoke-RestMethod https://fullmakt-test.minaombud.se/dfm/formedlare/v1/sok/behorigheter -Method POST -ContentType "application/json" -Headers @{Authorization="Bearer $access_token"; 'X-Service-Name'=$client_id; 'X-Id-Token'=$idtoken} -Body ($BeriYlles | ConvertTo-Json)
    $ErrResp   
    $behorigheter
   
} else {
    write-host "access_token has expired"-ForegroundColor Red

}