using System.Net;
using System.Net.Sockets;
using System.Reflection;
using SMBLibrary.Client;
using Xunit;

namespace SMBLibrary.Tests;

public class SMB1ClientSessionStateTests
{
    private static void SetField(SMB1Client client, string name, object value) =>
        typeof(SMB1Client).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(client, value);

    [Fact]
    public void Disconnect_ClearsTheLoggedInFlag()
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        Socket peer = listener.AcceptSocket();
        try
        {
            SMB1Client client = new SMB1Client();
            SetField(client, "m_clientSocket", socket);
            SetField(client, "m_connectionState", new ConnectionState(socket));
            SetField(client, "m_isConnected", true);
            SetField(client, "m_isLoggedIn", true);

            client.Disconnect();
            SetField(client, "m_isConnected", true);

            Assert.Throws<InvalidOperationException>(() => client.TreeConnect("share", out NTStatus _));
        }
        finally
        {
            peer.Dispose();
            listener.Stop();
        }
    }
}
