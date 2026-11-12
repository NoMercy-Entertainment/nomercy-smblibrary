using System.Reflection;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.RPC;
using SMBLibrary.Server;
using SMBLibrary.Services;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;
using Xunit;

namespace SMBLibrary.Tests;

internal class RecordingFileStore : INTFileStore
{
    public object SecurityHandle;
    public bool SecurityCalled;
    public bool QueryDirectoryCalled;
    public List<object> CanceledRequests = new List<object>();

    public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, SMBLibrary.FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
    {
        handle = null;
        fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
        return NTStatus.STATUS_NOT_SUPPORTED;
    }

    public NTStatus CloseFile(object handle) { return NTStatus.STATUS_SUCCESS; }
    public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount) { data = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data) { numberOfBytesWritten = 0; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus FlushFileBuffers(object handle) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus UnlockFile(object handle, long byteOffset, long length) { return NTStatus.STATUS_NOT_SUPPORTED; }

    public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName, FileInformationClass informationClass)
    {
        QueryDirectoryCalled = true;
        result = null;
        return NTStatus.STATUS_NOT_SUPPORTED;
    }

    public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus SetFileInformation(object handle, FileInformation information) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus SetFileSystemInformation(FileSystemInformation information) { return NTStatus.STATUS_NOT_SUPPORTED; }
    public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }

    public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
    {
        SecurityCalled = true;
        SecurityHandle = handle;
        return NTStatus.STATUS_SUCCESS;
    }

    public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
    {
        ioRequest = new object();
        return NTStatus.STATUS_PENDING;
    }

    public NTStatus Cancel(object ioRequest)
    {
        CanceledRequests.Add(ioRequest);
        return NTStatus.STATUS_SUCCESS;
    }

    public NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength) { output = null; return NTStatus.STATUS_NOT_SUPPORTED; }
}

internal static class SMB2ServerHarness
{
    internal static readonly Assembly Library = typeof(SMB2Client).Assembly;
    private const BindingFlags Any = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance;

    internal static (object state, object session) CreateSession()
    {
        object baseState = Activator.CreateInstance(Library.GetType("SMBLibrary.Server.ConnectionState"), new object[] { null, null, null });
        object state = Activator.CreateInstance(Library.GetType("SMBLibrary.Server.SMB2ConnectionState"), new object[] { baseState });
        object session = Call(state, "CreateSession", 1UL, "user", "machine", null, null, false, null);
        return (state, session);
    }

    internal static object Call(object target, string method, params object[] args)
    {
        try
        {
            MethodInfo info = target.GetType().GetMethods(Any).Single(m => m.Name == method && m.GetParameters().Length == args.Length);
            return info.Invoke(target, args);
        }
        catch (TargetInvocationException ex)
        {
            throw ex.InnerException;
        }
    }

    internal static object CallStatic(string typeName, string method, params object[] args)
    {
        try
        {
            return Library.GetType(typeName).GetMethod(method, Any).Invoke(null, args);
        }
        catch (TargetInvocationException ex)
        {
            throw ex.InnerException;
        }
    }

    internal static FileID OpenFile(object session, uint treeID, string shareName, object handle)
    {
        return ((FileID?)Call(session, "AddOpenFile", treeID, shareName, @"\dir", handle, System.IO.FileAccess.Read)).Value;
    }

    internal static NTStatus StatusOf(object response)
    {
        return ((SMB2Command)response).Header.Status;
    }
}

public class ChangeNotifyUnknownFileTests
{
    [Fact]
    public void UnknownFileId_ReturnsFileClosed()
    {
        var (state, session) = SMB2ServerHarness.CreateSession();
        var share = new FileSystemShare("data", new RecordingFileStore());
        ChangeNotifyRequest request = new ChangeNotifyRequest();
        request.Header.SessionID = 1;
        request.FileId = new FileID { Persistent = 77, Volatile = 77 };

        object response = SMB2ServerHarness.CallStatic("SMBLibrary.Server.SMB2.ChangeNotifyHelper", "GetChangeNotifyInterimResponse", request, share, state);

        Assert.Equal(NTStatus.STATUS_FILE_CLOSED, SMB2ServerHarness.StatusOf(response));
    }
}

public class QueryDirectoryOnPipeTests
{
    [Fact]
    public void QueryDirectoryOnNamedPipe_ReturnsErrorResponse()
    {
        var (state, session) = SMB2ServerHarness.CreateSession();
        var share = new NamedPipeShare(new List<string>());
        uint treeID = ((uint?)SMB2ServerHarness.Call(session, "AddConnectedTree", share)).Value;
        FileID fileId = SMB2ServerHarness.OpenFile(session, treeID, "IPC$", new object());
        QueryDirectoryRequest request = new QueryDirectoryRequest();
        request.Header.SessionID = 1;
        request.FileId = fileId;
        request.FileName = "*";

        object response = SMB2ServerHarness.CallStatic("SMBLibrary.Server.SMB2.QueryDirectoryHelper", "GetQueryDirectoryResponse", request, share, state);

        Assert.Equal(NTStatus.STATUS_NOT_SUPPORTED, SMB2ServerHarness.StatusOf(response));
    }
}

public class SetInfoSecurityHandleTests
{
    [Fact]
    public void SetSecurityInformation_ReceivesTheStoreHandle()
    {
        var (state, session) = SMB2ServerHarness.CreateSession();
        var store = new RecordingFileStore();
        var share = new FileSystemShare("data", store);
        uint treeID = ((uint?)SMB2ServerHarness.Call(session, "AddConnectedTree", share)).Value;
        object handle = new object();
        FileID fileId = SMB2ServerHarness.OpenFile(session, treeID, "data", handle);
        SetInfoRequest request = new SetInfoRequest();
        request.Header.SessionID = 1;
        request.InfoType = InfoType.Security;
        request.FileId = fileId;
        request.SecurityInformation = SecurityInformation.DACL_SECURITY_INFORMATION;
        request.SetSecurityInformation(new SecurityDescriptor());

        SMB2ServerHarness.CallStatic("SMBLibrary.Server.SMB2.SetInfoHelper", "GetSetInfoResponse", request, share, state);

        Assert.True(store.SecurityCalled);
        Assert.Same(handle, store.SecurityHandle);
    }
}

public class CancelAfterTreeDisconnectTests
{
    [Fact]
    public void CancelForDisconnectedTree_DoesNotThrow()
    {
        var (state, session) = SMB2ServerHarness.CreateSession();
        var share = new FileSystemShare("data", new RecordingFileStore());
        uint treeID = ((uint?)SMB2ServerHarness.Call(session, "AddConnectedTree", share)).Value;
        object context = SMB2ServerHarness.Call(state, "CreateAsyncContext", new FileID(), state, 1UL, treeID);
        ulong asyncId = (ulong)context.GetType().GetField("AsyncID").GetValue(context);
        SMB2ServerHarness.Call(session, "DisconnectTree", treeID);
        CancelRequest request = new CancelRequest();
        request.Header.SessionID = 1;
        request.Header.IsAsync = true;
        request.Header.AsyncID = asyncId;

        Exception error = Record.Exception(() => SMB2ServerHarness.CallStatic("SMBLibrary.Server.SMB2.CancelHelper", "GetCancelResponse", request, state));

        Assert.Null(error);
    }

    [Fact]
    public void CancelForUnknownTree_DoesNotThrow()
    {
        var (state, session) = SMB2ServerHarness.CreateSession();
        object context = SMB2ServerHarness.Call(state, "CreateAsyncContext", new FileID(), state, 1UL, 99u);
        ulong asyncId = (ulong)context.GetType().GetField("AsyncID").GetValue(context);
        CancelRequest request = new CancelRequest();
        request.Header.SessionID = 1;
        request.Header.IsAsync = true;
        request.Header.AsyncID = asyncId;

        Exception error = Record.Exception(() => SMB2ServerHarness.CallStatic("SMBLibrary.Server.SMB2.CancelHelper", "GetCancelResponse", request, state));

        Assert.Null(error);
    }

    [Fact]
    public void TreeDisconnect_RemovesPendingAsyncContexts()
    {
        var (state, session) = SMB2ServerHarness.CreateSession();
        var share = new FileSystemShare("data", new RecordingFileStore());
        uint treeID = ((uint?)SMB2ServerHarness.Call(session, "AddConnectedTree", share)).Value;
        object context = SMB2ServerHarness.Call(state, "CreateAsyncContext", new FileID(), state, 1UL, treeID);
        ulong asyncId = (ulong)context.GetType().GetField("AsyncID").GetValue(context);

        SMB2ServerHarness.Call(session, "DisconnectTree", treeID);

        Assert.Null(SMB2ServerHarness.Call(state, "GetAsyncContext", asyncId));
    }
}

public class FindFirst2AccessTests
{
    [Fact]
    public void FindFirst2_DeniedByAccessRequested_ReturnsAccessDenied()
    {
        Assembly library = SMB2ServerHarness.Library;
        object baseState = Activator.CreateInstance(library.GetType("SMBLibrary.Server.ConnectionState"), new object[] { null, null, null });
        object state = Activator.CreateInstance(library.GetType("SMBLibrary.Server.SMB1ConnectionState"), new object[] { baseState });
        object session = SMB2ServerHarness.Call(state, "CreateSession", "user", "machine", null, null);
        ushort userId = (ushort)session.GetType().GetProperty("UserID").GetValue(session);
        var store = new RecordingFileStore();
        var share = new FileSystemShare("data", store);
        share.AccessRequested += (sender, args) => args.Allow = false;
        SMB1Header header = new SMB1Header();
        header.UID = userId;
        Transaction2FindFirst2Request subcommand = new Transaction2FindFirst2Request();
        subcommand.FileName = @"\private\*";
        subcommand.InformationLevel = FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO;
        subcommand.SearchCount = 10;

        MethodInfo method = library.GetType("SMBLibrary.Server.SMB1.Transaction2SubcommandHelper")
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(m => m.Name == "GetSubcommandResponse" && m.GetParameters()[2].ParameterType == typeof(Transaction2FindFirst2Request));
        method.Invoke(null, new object[] { header, 4096u, subcommand, share, state });

        Assert.Equal(NTStatus.STATUS_ACCESS_DENIED, header.Status);
    }
}

public class ShareInfoRoundTripTests
{
    [Fact]
    public void Level0_RoundTrips()
    {
        NetrShareGetInfoResponse response = new NetrShareGetInfoResponse { InfoStruct = new ShareInfo(new ShareInfo0Entry("data")) };

        NetrShareGetInfoResponse parsed = new NetrShareGetInfoResponse(response.GetBytes());

        Assert.Equal(0u, parsed.InfoStruct.Level);
        Assert.Equal("data", ((ShareInfo0Entry)parsed.InfoStruct.Info).NetName.Value);
    }

    [Fact]
    public void Level1_RoundTrips()
    {
        ShareInfo1Entry entry = new ShareInfo1Entry("data", new ShareTypeExtended(SMBLibrary.Services.ShareType.DiskDrive));
        NetrShareGetInfoResponse response = new NetrShareGetInfoResponse { InfoStruct = new ShareInfo(entry) };

        NetrShareGetInfoResponse parsed = new NetrShareGetInfoResponse(response.GetBytes());

        Assert.Equal(1u, parsed.InfoStruct.Level);
        Assert.Equal("data", ((ShareInfo1Entry)parsed.InfoStruct.Info).NetName.Value);
    }

    [Fact]
    public void Level2_RoundTrips()
    {
        ShareInfo2Entry entry = new ShareInfo2Entry("data", new ShareTypeExtended(SMBLibrary.Services.ShareType.DiskDrive));
        NetrShareGetInfoResponse response = new NetrShareGetInfoResponse { InfoStruct = new ShareInfo(entry) };

        NetrShareGetInfoResponse parsed = new NetrShareGetInfoResponse(response.GetBytes());

        Assert.Equal(2u, parsed.InfoStruct.Level);
        Assert.Equal("data", ((ShareInfo2Entry)parsed.InfoStruct.Info).NetName.Value);
    }
}
