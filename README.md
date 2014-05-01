
## PowerBleed

Powerbleed is a powershell module that allows you to check for the OpenSSL heartbeat
vulnerability, exploit it and write data to a file if desired.  Powerbleed defaults
to checking web based SSL/TLS on port 443, however will also support STARTTLS
based functionality for other protocols such as SMTP, IMAP, POP, and FTP.
Only a single heartbeat, and TLS connection is attempted by default after
heartbeat support is ascertained in the initial check.   This can be modified with the TLSTries,
and Heartbeats parameters.  By default, a random delay is introduced between heartbeats
which can be disabled if desired also.

**Author: Joff Thyer, April-May 2014**

**Concept suggestion by Tim Tomes.**


## Sponsors

[![Black Hills Information Security](http://www.blackhillsinfosec.com/_images/BHIS-Logo.png)](http://www.blackhillsinfosec.com)


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

**Author: Joff Thyer, April 2014
**Version: 20140501-1011
**Acknowledgments to Tim Tomes.

.EXAMPLE

Usage example within CMD.EXE only.  Assumes that module is contained within
current working directory.

C:\> `powershell -command (Import-Module ./powerbleed.psm1); Test-Heartbleed -Computername 10.10.1.150 -Verbose`

Powershell interactive usage examples:

PS C:\> `Import-Module ./powerbleed.psm1`
PS C:\> `Test-Heartbleed -Computername 10.10.1.150 -Heartbeats 5 -HBLen 32767 -Verbose`

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

PS C:\> `Test-Heartbleed -Computername 10.10.1.150 |
		Select-Object -ExpandProperty Bytes |
		Set-Content -Encoding Byte -Path ./file.txt`

PS C:\> `Test-Heartbleed -Computername 10.10.1.150 | Select-Object -ExpandProperty Bytes | Set-Content -Encoding Byte -Path ./file.txt`

Or as a one line command with no pipeline with the -WriteFile argument.

PS C:\> `Test-Heartbleed -Computername 10.10.1.150 -WriteFile`


Other examples:

PS C:\> `Test-Heartbleed -Computername 10.10.1.150 -Heartbeats 3 -TLSTries 3 -NoRandomDelay -Verbose`

PS C:\> `Test-Heartbleed -Computername smtp.domain.tld -Port 25 -STLSProto SMTP -Verbose`


