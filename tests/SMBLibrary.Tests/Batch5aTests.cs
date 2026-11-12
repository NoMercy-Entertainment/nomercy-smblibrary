using System.Net;
using System.Net.Sockets;
using System.Reflection;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.NetBios;
using SMBLibrary.RPC;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;
using Xunit;
using ErrorResponse = SMBLibrary.SMB2.ErrorResponse;
using EchoResponse = SMBLibrary.SMB2.EchoResponse;

namespace SMBLibrary.Tests;

internal static class Batch5aReflection
{
    internal const BindingFlags Instance = BindingFlags.NonPublic | BindingFlags.Instance;

    internal static void Set(SMB2Client client, string name, object value) =>
        typeof(SMB2Client).GetField(name, Instance)!.SetValue(client, value);

    internal static object Get(SMB2Client client, string name) =>
        typeof(SMB2Client).GetField(name, Instance)!.GetValue(client)!;

    internal static void ProcessPacket(SMB2Client client, SessionPacket packet, ConnectionState state)
    {
        try
        {
            typeof(SMB2Client).GetMethod("ProcessPacket", Instance)!.Invoke(client, new object[] { packet, state });
        }
        catch (TargetInvocationException ex)
        {
            throw ex.InnerException!;
        }
    }

    internal static ConnectionState NewState() =>
        new ConnectionState(new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp));
}

public class EncryptedPacketFailureTests
{
    [Fact]
    public void TransformPacket_WithABadTag_ClosesTheConnectionInsteadOfThrowing()
    {
        SMB2Client client = new SMB2Client();
        Batch5aReflection.Set(client, "m_dialect", SMB2Dialect.SMB300);
        Batch5aReflection.Set(client, "m_decryptionKey", new byte[16]);
        Batch5aReflection.Set(client, "m_isConnected", true);

        SMB2TransformHeader header = new SMB2TransformHeader
        {
            Signature = new byte[16],
            Nonce = new byte[16],
            OriginalMessageSize = 64,
        };
        byte[] trailer = new byte[SMB2TransformHeader.Length + 64];
        header.WriteBytes(trailer, 0);
        SessionMessagePacket packet = new SessionMessagePacket { Trailer = trailer };

        Exception error = Record.Exception(() => Batch5aReflection.ProcessPacket(client, packet, Batch5aReflection.NewState()));

        Assert.Null(error);
        Assert.False(client.IsConnected);
    }

    [Fact]
    public void TransformPacket_BeforeKeysExist_ClosesTheConnectionInsteadOfThrowing()
    {
        SMB2Client client = new SMB2Client();
        Batch5aReflection.Set(client, "m_dialect", SMB2Dialect.SMB300);
        Batch5aReflection.Set(client, "m_isConnected", true);

        SMB2TransformHeader header = new SMB2TransformHeader
        {
            Signature = new byte[16],
            Nonce = new byte[16],
            OriginalMessageSize = 64,
        };
        byte[] trailer = new byte[SMB2TransformHeader.Length + 64];
        header.WriteBytes(trailer, 0);
        SessionMessagePacket packet = new SessionMessagePacket { Trailer = trailer };

        Exception error = Record.Exception(() => Batch5aReflection.ProcessPacket(client, packet, Batch5aReflection.NewState()));

        Assert.Null(error);
        Assert.False(client.IsConnected);
    }
}

public class SMB2ClientResetTests
{
    private static void FillSessionState(SMB2Client client)
    {
        Batch5aReflection.Set(client, "m_isLoggedIn", true);
        Batch5aReflection.Set(client, "m_encryptSessionData", true);
        Batch5aReflection.Set(client, "m_signingRequired", true);
        Batch5aReflection.Set(client, "m_signingKey", new byte[16]);
        Batch5aReflection.Set(client, "m_encryptionKey", new byte[16]);
        Batch5aReflection.Set(client, "m_decryptionKey", new byte[16]);
        Batch5aReflection.Set(client, "m_sessionKey", new byte[16]);
        Batch5aReflection.Set(client, "m_messageID", 9u);
        Batch5aReflection.Set(client, "m_sessionID", 5UL);
        ((System.Collections.IList)Batch5aReflection.Get(client, "m_incomingQueue")).Add(new EchoResponse());
    }

    private static void AssertClean(SMB2Client client)
    {
        Assert.False((bool)Batch5aReflection.Get(client, "m_isLoggedIn"));
        Assert.False((bool)Batch5aReflection.Get(client, "m_encryptSessionData"));
        Assert.False((bool)Batch5aReflection.Get(client, "m_signingRequired"));
        Assert.Null(Batch5aReflection.Get(client, "m_signingKey") as byte[]);
        Assert.Null(Batch5aReflection.Get(client, "m_encryptionKey") as byte[]);
        Assert.Null(Batch5aReflection.Get(client, "m_decryptionKey") as byte[]);
        Assert.Null(Batch5aReflection.Get(client, "m_sessionKey") as byte[]);
        Assert.Empty((System.Collections.IList)Batch5aReflection.Get(client, "m_incomingQueue"));
    }

    [Fact]
    public void Disconnect_ClearsKeysFlagsAndTheIncomingQueue()
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        Socket peer = listener.AcceptSocket();
        try
        {
            SMB2Client client = new SMB2Client();
            Batch5aReflection.Set(client, "m_clientSocket", socket);
            Batch5aReflection.Set(client, "m_connectionState", new ConnectionState(socket));
            Batch5aReflection.Set(client, "m_isConnected", true);
            FillSessionState(client);

            client.Disconnect();

            AssertClean(client);
        }
        finally
        {
            peer.Dispose();
            listener.Stop();
        }
    }

    [Fact]
    public void Connect_AfterTheServerDroppedTheConnection_StartsFromCleanState()
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            SMB2Client client = new SMB2Client(200);
            FillSessionState(client);

            client.Connect(IPAddress.Loopback, SMBTransportType.DirectTCPTransport, ((IPEndPoint)listener.LocalEndpoint).Port);

            AssertClean(client);
        }
        finally
        {
            listener.Stop();
        }
    }
}

public class OplockBreakNotificationTests
{
    private static byte[] NotificationBytes()
    {
        byte[] header = new ErrorResponse(SMB2CommandName.OplockBreak).GetBytes().Take(SMB2Header.Length).ToArray();
        byte[] body = new byte[24];
        body[0] = 24;
        return header.Concat(body).ToArray();
    }

    [Fact]
    public void ReadResponse_ParsesAnOplockBreakNotification()
    {
        Exception error = Record.Exception(() => SMB2Command.ReadResponse(NotificationBytes(), 0));

        Assert.Null(error);
    }

    [Fact]
    public void ProcessPacket_KeepsTheConnectionOpenOnAnOplockBreakNotification()
    {
        SMB2Client client = new SMB2Client();
        Batch5aReflection.Set(client, "m_isConnected", true);
        SessionMessagePacket packet = new SessionMessagePacket { Trailer = NotificationBytes() };

        Batch5aReflection.ProcessPacket(client, packet, Batch5aReflection.NewState());

        Assert.True(client.IsConnected);
    }
}

internal class ScriptedPipeStore : INTFileStore
{
    public int CloseCount;
    public Queue<(NTStatus status, byte[] output)> Replies = new Queue<(NTStatus, byte[])>();

    public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, SMBLibrary.FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
    {
        handle = new object();
        fileStatus = FileStatus.FILE_OPENED;
        return NTStatus.STATUS_SUCCESS;
    }

    public NTStatus CloseFile(object handle) { CloseCount++; return NTStatus.STATUS_SUCCESS; }

    public NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength)
    {
        var reply = Replies.Dequeue();
        output = reply.output;
        return reply.status;
    }

    public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount) { data = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data) { numberOfBytesWritten = 0; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus FlushFileBuffers(object handle) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus UnlockFile(object handle, long byteOffset, long length) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName, FileInformationClass informationClass) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus SetFileInformation(object handle, FileInformation information) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus SetFileSystemInformation(FileSystemInformation information) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context) { ioRequest = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus Cancel(object ioRequest) { return NTStatus.STATUS_SUCCESS; }
}

public class PipeHandleLeakTests
{
    private static readonly Guid InterfaceGuid = new Guid("4b324fc8-1670-01d3-1278-5a47bf6ee188");

    [Fact]
    public void BindPipe_ClosesThePipeWhenTheTransceiveFails()
    {
        ScriptedPipeStore store = new ScriptedPipeStore();
        store.Replies.Enqueue((NTStatus.STATUS_ACCESS_DENIED, null));

        NTStatus status = NamedPipeHelper.BindPipe(store, "srvsvc", InterfaceGuid, 3, out _, out _);

        Assert.Equal(NTStatus.STATUS_ACCESS_DENIED, status);
        Assert.Equal(1, store.CloseCount);
    }

    [Fact]
    public void BindPipe_ClosesThePipeWhenTheReplyIsNotABindAck()
    {
        ScriptedPipeStore store = new ScriptedPipeStore();
        store.Replies.Enqueue((NTStatus.STATUS_SUCCESS, new ResponsePDU { Data = new byte[0] }.GetBytes()));

        NTStatus status = NamedPipeHelper.BindPipe(store, "srvsvc", InterfaceGuid, 3, out _, out _);

        Assert.Equal(NTStatus.STATUS_NOT_SUPPORTED, status);
        Assert.Equal(1, store.CloseCount);
    }

    [Fact]
    public void ListShares_ClosesThePipeWhenTheEnumerationFails()
    {
        ScriptedPipeStore store = new ScriptedPipeStore();
        store.Replies.Enqueue((NTStatus.STATUS_SUCCESS, new BindAckPDU { MaxTransmitFragmentSize = 5680 }.GetBytes()));
        store.Replies.Enqueue((NTStatus.STATUS_ACCESS_DENIED, null));

        var shares = ServerServiceHelper.ListShares(store, "TEST", null, out NTStatus status);

        Assert.Null(shares);
        Assert.Equal(NTStatus.STATUS_ACCESS_DENIED, status);
        Assert.Equal(1, store.CloseCount);
    }
}

public class SMB2FlushStatusTests
{
    [Fact]
    public void FlushFileBuffers_ReturnsTheServerErrorStatus()
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        Socket peer = listener.AcceptSocket();
        try
        {
            SMB2Client client = new SMB2Client(500);
            Batch5aReflection.Set(client, "m_clientSocket", socket);
            Batch5aReflection.Set(client, "m_isConnected", true);
            ErrorResponse reply = new ErrorResponse(SMB2CommandName.Flush);
            reply.Header.MessageID = 0;
            reply.Header.Status = NTStatus.STATUS_ACCESS_DENIED;
            ((System.Collections.IList)Batch5aReflection.Get(client, "m_incomingQueue")).Add(reply);
            SMB2FileStore store = new SMB2FileStore(client, 1, false);

            NTStatus status = store.FlushFileBuffers(new FileID());

            Assert.Equal(NTStatus.STATUS_ACCESS_DENIED, status);
        }
        finally
        {
            peer.Dispose();
            socket.Dispose();
            listener.Stop();
        }
    }
}

public class FileTimeClampTests
{
    [Fact]
    public void ReadNullableFileTime_ClampsAValueBeyondTheDateTimeRange()
    {
        byte[] buffer = BitConverter.GetBytes(long.MaxValue);

        DateTime? result = null;
        Exception error = Record.Exception(() => result = FileTimeHelper.ReadNullableFileTime(buffer, 0));

        Assert.Null(error);
        Assert.Equal(DateTime.MaxValue, result);
    }
}

public class Batch5aServerTransactTests
{
    private const string NTHelper = "SMBLibrary.Server.SMB1.NTTransactHelper";
    private const string Helper = "SMBLibrary.Server.SMB1.TransactionHelper";

    [Fact]
    public void NTTransactSecondary_WithoutAFirstRequest_ReturnsInvalidSmb()
    {
        object state = Smb1Internals.CreateState();
        SMB1Header header = new SMB1Header { PID = 11 };
        NTTransactSecondaryRequest secondary = new NTTransactSecondaryRequest { TransParameters = new byte[0], TransData = new byte[4] };

        List<SMB1Command>? response = null;
        Exception error = Record.Exception(() => response = (List<SMB1Command>)Smb1Internals.Static(NTHelper, "GetNTTransactResponse", header, secondary, null!, state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_INVALID_SMB, header.Status);
    }

    [Fact]
    public void FirstTransaction_WithMoreDataThanDeclared_ReturnsInvalidParameter()
    {
        object state = Smb1Internals.CreateState();
        SMB1Header header = new SMB1Header { PID = 12 };
        TransactionRequest first = new TransactionRequest
        {
            TotalParameterCount = 10,
            TotalDataCount = 2,
            Setup = new byte[0],
            Name = @"\PIPE\srvsvc",
            TransParameters = new byte[2],
            TransData = new byte[5],
        };

        Exception error = Record.Exception(() => Smb1Internals.Static(Helper, "GetTransactionResponse", header, first, new StubShare(new StubFileStore()), state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_INVALID_PARAMETER, header.Status);
    }
}
