function logo {
  $loop = $true
  while ($loop) {
@"
  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\
  ( -.- )( o.o )( $.$ )( @.@ )( <.< )( =.= )( >.> )( *.* )( ^.^ )( `.` )
  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <
  /\_/\       _____                       __            __       /\_/\
  ( x.x )     /     \   ____   ___________|  | _______ _/  |_    ( Q.Q )
  > ^ <     /  \ /  \_/ __ \_/ __ \_  __ \  |/ /\__  \\   __\    > ^ <
  /\_/\    /    Y    \  ___/\  ___/|  | \/    <  / __ \|  |      /\_/\
  ( v.v )   \____|__  /\___  >\___  >__|  |__|_ \(____  /__|     ( ~.~ )
  > ^ <            \/     \/     \/           \/     \/          > ^ <
  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\
  ( Q.Q )( w.w )( !.! )( #.# )( '.' )( u.u )( $.$ )( &.& )( 0.0 )( x.x )
  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <
  1.Local System Enumeration
  2.Find Active Devices and Open ports
  3.Network traffic
  4.Privilege Escalation
  5.Check AD status
  6.Exit Program
"@
    $option = Read-Host "[Option]:"
    switch ($option) {
      "1" { enumeration }
      "2" { PingDevicesAndPorts }
      "3" { NetworkTraffic }
      "4" { PrivledgeEscalation }
      "5" { CheckActiveDirectory }
      "6" { $loop = $false }
      Default { Write-Host "Invalid option. Try again." }
    }
  }
}


function enumeration{
  param()
  Write-Host "[Local System Enumeration]" -ForegroundColor Red
  Write-Host "Systeminfo" -ForegroundColor Green
  systeminfo.exe

}


function PingDevicesAndPorts{
  param()
  Write-Host "[Scanning for Active Devices and Open ports]" -ForegroundColor Red
  $Subnet = "10.73.228."
  $ActiveDevices = @{}
  $PortsToScan = @(80,8080,443,110,53,21,22,3306,3389)




  #pings devices to see status
  for($i = 0; $i -le 254; $i++){
    $ip = "$Subnet$i"
    #if status is active, saves IP to dict
    if(Test-Connection -ComputerName $ip -Count 1 -Quiet){
      $ActiveDevices[$ip] = @()
      Write-Host "$ip Active" -ForegroundColor Green
    }
  }


  #port scans all the devices that statuses were active
  foreach($device in $ActiveDevices.Keys){
    foreach($port in $PortsToScan){
      $socket = New-Object System.Net.Sockets.TcpClient
      $socket.ConnectAsync($device, $port).Wait(100)
      if($socket.Connected){
        Write-Host "Port $port is open on $device" -ForegroundColor Green
        $ActiveDevices[$device]+=$port
      }
      $socket.Close()
    }
  }


  for($i = 0; $i -le 254; $i++){
    $ip = "$subnet$i"
    if($ActiveDevices.ContainsKey($ip)){
      continue
    }
    foreach($port in $PortsToScan){
      $socket = New-Object System.Net.Sockets.TcpClient
      $socket.ConnectAsync($ip, $port).Wait(100)




      if($socket.Connected){
        Write-Host "Port $port open on inactive IP: $ip" -ForegroundColor Green
        $ActiveDevices[$ip] = @($port)
      }
      $socket.Close()
    }
  }


  foreach ($device in $ActiveDevices.GetEnumerator()) {
      Write-Host "Device: $($device.Key)"
      Write-Host "Open Ports: $($device.Value -join ', ')"
      Write-Host ""
  }
}


function CheckActiveDirectory{
  param()
  Write-Host "[Checking for Active Directory]" -ForegroundColor Red
  if((Get-WmiObject Win32_ComputerSystem).PartofDomain){
    Write-Host "Active Directory Active" -ForegroundColor Green
  }
  else{
    Write-Host "No Active Directory"
  }
  try{
    Get-SmbShare
  }
  catch{
    Write-Host "No SMB Share"
  }


  try{
    #require-s RSTA tools(AD module) to be installed
    Get-ADComputer -Identity $env:COMPUTERNAME
    Test-ComputerSecureChannel
    Get-ADDomain
  }
  catch{
    Write-Host "No Active Directory" -ForegroundColor Green
  }
}




function NetworkTraffic{
 
  param()
 
  if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    admin
  }
  else {
    notadmin
  }


  function notadmin {
    param ()
    Write-Host "Currently not admin. Can only check Network Status, Not see traffic"
    Write-Host "[Checking for any Network Traffic]" -ForegroundColor Red
    $Adapters = @()
    $Adapters+=Get-NetAdapter | Select-Object -ExpandProperty Name
   
    foreach($adapter in $Adapters){
      try{
        $before = (Get-NetAdapterStatistics -Name $adapter -ErrorAction Stop).ReceivedBytes
        Start-Sleep -Seconds 5
        $after = (Get-NetAdapterStatistics -Name $adapter -ErrorAction Stop).ReceivedBytes
       
        if ($after -gt $before) {
            Write-Host "Traffic detected on $adapter" -ForegroundColor Green
        }
        else{
            "No traffic detected on $adapter"
        }
      }
      catch{}
    }
   
  }


  function admin {
    param ()
    continue
  }
}


function PrivledgeEscalation {
  param ()
  continue
}

logo