using System.Net;
using System.Net.Sockets;
using System.Reflection;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.NetBios;
using SMBLibrary.Server;
using SMBLibrary.SMB2;
using Xunit;

namespace SMBLibrary.Tests;

public class Batch5bTests
{
    private const BindingFlags NonPublicInstance = BindingFlags.NonPublic | BindingFlags.Instance;
    private static readonly Assembly Library = typeof(SMBServer).Assembly;

    private static object NewConnectionState()
    {
        return Activator.CreateInstance(Library.GetType("SMBLibrary.Server.ConnectionState"), new object[] { null, null, null });
    }

    private static object NewSmb2State()
    {
        return Activator.CreateInstance(Library.GetType("SMBLibrary.Server.SMB2ConnectionState"), new object[] { NewConnectionState() });
    }

    // Holds the lock from the test thread and reports whether the action finished while it was held.
    private static bool CompletesWhileLockHeld(object lockTarget, Action action)
    {
        bool completed;
        lock (lockTarget)
        {
            Task task = Task.Run(action);
            completed = task.Wait(500);
        }
        return completed;
    }

    // #11 AUD-7159
    [Fact]
    public void NameServer_MalformedNameQuery_IsIgnored()
    {
        NameServer server = new NameServer(IPAddress.Loopback, IPAddress.Parse("255.0.0.0"));
        using UdpClient listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using UdpClient sender = new UdpClient();
        typeof(NameServer).GetField("m_client", NonPublicInstance).SetValue(server, listener);
        typeof(NameServer).GetField("m_listening", NonPublicInstance).SetValue(server, true);

        NameQueryRequest request = new NameQueryRequest();
        request.Header.QDCount = 1;
        request.Question.Name = NetBiosUtils.GetMSNetBiosName("TEST", NetBiosSuffix.WorkstationService);
        byte[] valid = request.GetBytes();
        // Swap the 32 character encoded label for a 4 character one, which decodes to a 2 character name
        int headerLength = NameServicePacketHeader.Length;
        byte[] label = System.Text.Encoding.ASCII.GetBytes("CECF");
        byte[] packet = valid.Take(headerLength).Concat(new byte[] { 4 }).Concat(label).Concat(valid.Skip(headerLength + 1 + 32)).ToArray();
        sender.Send(packet, packet.Length, (IPEndPoint)listener.Client.LocalEndPoint);
        IAsyncResult result = listener.BeginReceive(null, null);
        Assert.True(result.AsyncWaitHandle.WaitOne(2000));

        MethodInfo callback = typeof(NameServer).GetMethod("ReceiveCallback", NonPublicInstance);
        Exception error = Record.Exception(() => callback.Invoke(server, new object[] { result }));

        Assert.Null(error);
    }

    // #14 AUD-7162
    [Fact]
    public void Smb2AsyncIdAllocation_WaitsForPendingRequestsLock()
    {
        object state = NewSmb2State();
        object pending = state.GetType().GetField("m_pendingRequests", NonPublicInstance).GetValue(state);
        MethodInfo allocate = state.GetType().GetMethod("AllocateAsyncID", NonPublicInstance);

        bool completed = CompletesWhileLockHeld(pending, () => allocate.Invoke(state, null));

        Assert.False(completed);
    }

    [Fact]
    public void Smb2CreateAsyncContext_ConcurrentCallsGetUniqueIds()
    {
        object state = NewSmb2State();
        MethodInfo create = state.GetType().GetMethod("CreateAsyncContext");
        List<Exception> errors = new List<Exception>();
        Task[] tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < 2000; i++)
            {
                try
                {
                    create.Invoke(state, new object[] { default(FileID), state, 1UL, 1U });
                }
                catch (Exception ex)
                {
                    lock (errors) { errors.Add(ex); }
                    return;
                }
            }
        })).ToArray();
        Task.WaitAll(tasks);

        Assert.Empty(errors);
    }

    // #17 AUD-7165
    [Fact]
    public void SmbServer_FailedStart_AllowsLaterStart()
    {
        TcpListener blocker = new TcpListener(IPAddress.Loopback, 0);
        blocker.Start();
        int port = ((IPEndPoint)blocker.LocalEndpoint).Port;
        SMBServer server = new SMBServer(new SMBShareCollection(), null);
        MethodInfo start = typeof(SMBServer).GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
            .Single(m => m.Name == "Start" && m.GetParameters().Length == 7);
        object[] args = { IPAddress.Loopback, SMBTransportType.DirectTCPTransport, port, true, true, false, null };

        try
        {
            Assert.NotNull(Record.Exception(() => start.Invoke(server, args)));
            blocker.Stop();

            Assert.Null(Record.Exception(() => start.Invoke(server, args)));
            using TcpClient client = new TcpClient();
            client.Connect(IPAddress.Loopback, port);
            Assert.True(client.Connected);
        }
        finally
        {
            blocker.Stop();
            server.Stop();
        }
    }

    // #18 AUD-7166
    [Fact]
    public void NameServiceClient_SilentHost_TimesOut()
    {
        using UdpClient silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)silent.Client.LocalEndPoint).Port;
        object client = Activator.CreateInstance(typeof(NameServiceClient), NonPublicInstance | BindingFlags.Public | BindingFlags.Instance, null,
            new object[] { IPAddress.Loopback, port, 300 }, null);

        Task<string> task = Task.Run(() => ((NameServiceClient)client).GetServerName());

        Assert.True(task.Wait(5000));
        Assert.Null(task.Result);
    }

    // #37 AUD-7185
    [Fact]
    public void ConnectionManager_KeepAliveCopiesListUnderLock()
    {
        object manager = Activator.CreateInstance(Library.GetType("SMBLibrary.Server.ConnectionManager"));
        object connections = manager.GetType().GetField("m_activeConnections", NonPublicInstance).GetValue(manager);
        MethodInfo keepAlive = manager.GetType().GetMethod("SendSMBKeepAlive");

        bool completed = CompletesWhileLockHeld(connections, () => keepAlive.Invoke(manager, new object[] { TimeSpan.FromMinutes(1) }));

        Assert.False(completed);
    }

    [Fact]
    public void ConnectionManager_ReleaseAllCopiesListUnderLock()
    {
        object manager = Activator.CreateInstance(Library.GetType("SMBLibrary.Server.ConnectionManager"));
        object connections = manager.GetType().GetField("m_activeConnections", NonPublicInstance).GetValue(manager);
        MethodInfo releaseAll = manager.GetType().GetMethod("ReleaseAllConnections");

        bool completed = CompletesWhileLockHeld(connections, () => releaseAll.Invoke(manager, null));

        Assert.False(completed);
    }

    // #44 AUD-7192
    [Fact]
    public void GetRelativeSharePath_UncPath_ReturnsPathInsideShare()
    {
        Assert.Equal(@"\*", ServerPathUtils.GetRelativeSharePath(@"\\192.0.2.1\Shared\*"));
        Assert.Equal(@"\", ServerPathUtils.GetRelativeSharePath(@"\\192.0.2.1\Shared"));
    }
}
