// Built with Windows PowerShell's .NET Framework compiler, including ARM64.
using System;
using System.Net;
using System.Net.Sockets;

public static class OfflineNetworkProbe
{
    public static int Main(string[] arguments)
    {
        using (var socket = new TcpClient(AddressFamily.InterNetwork))
        {
            try
            {
                var connection = socket.BeginConnect(IPAddress.Parse(arguments[0]), 443, null, null);
                if (!connection.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(10)))
                {
                    Console.Error.WriteLine("TCP probe timed out; this does not prove network denial");
                    return 1;
                }
                socket.EndConnect(connection);
                Console.WriteLine("TCP connected");
                return 0;
            }
            catch (SocketException error)
            {
                Console.WriteLine("socket error: " + error.NativeErrorCode);
                // WSAEACCES: a timeout or unrelated connection failure is not evidence.
                return error.SocketErrorCode == SocketError.AccessDenied ? 42 : 1;
            }
        }
    }
}
