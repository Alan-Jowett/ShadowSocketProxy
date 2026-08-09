param(
    [Parameter(Mandatory = $true)]
    [string] $BindAddress,
    [Parameter(Mandatory = $true)]
    [int] $Port,
    [Parameter(Mandatory = $true)]
    [string] $Marker
)

$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Parse($BindAddress),
    $Port
)
$listener.Start()
try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $buffer = New-Object byte[] 4096
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) {
                continue
            }
            $response = [Text.Encoding]::UTF8.GetBytes(
                "$Marker|$($client.Client.RemoteEndPoint)`n"
            )
            $stream.Write($response, 0, $response.Length)
            $stream.Flush()
        }
        finally {
            $client.Dispose()
        }
    }
}
finally {
    $listener.Stop()
}
