#Joshua Rudy
#July 2019


#Modify ExecutionPolicy to allow scripts to run
Set-ExecutionPolicy Unrestricted

#Assign variables to our IOC lists. This will save time later.
#[array] $files = Get-Content 'C:\Users\username\Desktop\Comment_Crew\Files.txt'
[array] $ips = Get-Content 'C:\Users\username\Desktop\Comment_Crew\IPs.txt'
#[array] $reg = Get-Content 'C:\Users\username\Desktop\Comment_Crew\Registry.txt'
[array] $domains = Get-Content 'C:\Users\username\Desktop\Comment_Crew\Domains.txt'
[array] $GETS = Get-Content 'C:\Users\username\Desktop\Comment_Crew\GET_Requests.txt'
[array] $POSTS = Get-Content 'C:\Users\username\Desktop\Comment_Crew\POST.txt'
$sid = 1000001



#Use the IP iocs and the domains to create snort rules
new-item -Path C:\Snort\rules -name local.rules -ErrorAction SilentlyContinue
foreach($ip in $ips){Write-host "Creating Snort rule for $ip";Add-Content C:\Snort\rules\local.rules -Value "alert ip any any <> $ip any (msg:""BAD IP found!""; sid:$sid;)";$sid++}
foreach($domain in $domains){Write-host "Creating Snort PCRE rule for $domain";Add-content C:\Snort\rules\local.rules -Value "alert udp any any <> any any (msg:""BAD domain $domain found!""; pcre:""/$domain/"";sid:$sid;)"; $sid++}
foreach($GET in $GETS){Write-Host "Creating Snort Content rule for GET $GET";Add-content C:\Snort\rules\local.rules -Value "alert tcp any any <> any any (msg:""GET $GET found!""; content:""GET"";sid:$sid;)"; $sid++}
foreach($POST in $POSTS){Write-Host "Creating Snort Content rule for POST $POST";Add-content C:\Snort\rules\local.rules -Value "alert tcp any any <> any any  (msg:""POST $POST found!""; content:""POST"";sid:$sid;)"; $sid++}

#Start Snort to populate alerts. Using -NoNewWindow to have this run as a background process
#start-process C:\Snort\bin\snort.exe -ArgumentList "-A console -i1 -c C:\Snort\etc\snort.conf -K ascii"

start-process C:\Snort\bin\snort.exe -ArgumentList " -i1 -c C:\Snort\etc\snort.conf -K ascii -l C:\snort\log\"


#Tail the alert.ids
Get-content C:\Snort\log\alert.ids
