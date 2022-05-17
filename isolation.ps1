##################################################################################
# Simple IR script for traffic isolation following malware detection, whilst allowing 
# AV operations and trusted remote management - Albert Davies 17/05/2022
##################################################################################


# Get args
param(
   [string] $option
)

# Static Vars
$rmm='137.137.137.137'  # Remote managment server IP
$fqdn = @('sophos_avi_servies.com','ms_atp_services.com','another_av_vendor.net')    # whitelist via DNS
$ips = @($rmm)      # Init ips 

# Get Sophos IPS
Write-Host "[*] Initializing..."
foreach ($i in $fqdn) {
    $result = Test-Connection $i -count 1 -ErrorAction SilentlyContinue;
    if ($result.IPV4Address)
        {
        $ips += $result.IPV4Address
    }
}

# Static Functions
# Create Firewall ALLOW rules 
function AllowIps{
    $ips = $ips | Select-Object -Unique
    foreach ($p in $ips) {
        Write-Host "[*] Allowing $p"
        netsh advfirewall firewall add rule name="Allow from $p in" dir=in action=allow protocol=ANY remoteip=$p
        netsh advfirewall firewall add rule name="Allow from $p out" dir=out action=allow protocol=ANY remoteip=$p
        Write-Host "[*] Completed"
    }
}

# Function for stopping ALL traffic
function StopTraffic{
    try {
        Write-Host "[*] Stopping all traffic"
        netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
    }
    catch {
        Write-Host "[!] Failed to reset firewall rules"
        StartTraffic
    }
}

# Function for reseting firewall rules back to defaults
function StartTraffic{
    try {
        Write-Host "[*] Unblocking firewall rules"
        netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound
        Write-Host "[*] Completed"

        # Remove Sophos/RMM temp rules
        Write-Host "[*] Removing temp firewall rules"
        $ips = $ips | Select-Object -Unique
        foreach ($p in $ips) {
            Write-Host "[*] Removiong $p allow rule"
            netsh advfirewall firewall delete rule name="Allow from $p in" dir=in 
            netsh advfirewall firewall delete rule name="Allow from $p out" dir=out 
            Write-Host "[*] Completed"
        }
    }
    catch {
        Write-Host "[!] Failed to reset firewall rules"
    }
}

# MAIN
if ($option -eq 'start') {
    StartTraffic;
}
elseif ($option -eq 'stop') {    
    StopTraffic;
    AllowIps;
}
else {
    Write-Host "Invalid argument - script requiers either 'start' or 'stop'";
}