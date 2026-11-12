using System.Reflection;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Server;
using SMBLibrary.SMB1;
using Xunit;

namespace SMBLibrary.Tests;

internal class StubFileStore : INTFileStore
{
    public NTStatus NotifyChangeStatus = NTStatus.STATUS_NOT_SUPPORTED;
    public NTStatus GetFileInformationStatus = NTStatus.STATUS_SUCCESS;
    public NTStatus DeviceIOControlStatus = NTStatus.STATUS_SUCCESS;

    public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
    {
        handle = new object();
        fileStatus = FileStatus.FILE_OPENED;
        return NTStatus.STATUS_SUCCESS;
    }

    public NTStatus CloseFile(object handle) => NTStatus.STATUS_SUCCESS;

    public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount) { data = null; return NTStatus.STATUS_NOT_SUPPORTED; }

    public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data) { numberOfBytesWritten = 0; return NTStatus.STATUS_NOT_SUPPORTED; }

    public NTStatus FlushFileBuffers(object handle) => NTStatus.STATUS_NOT_SUPPORTED;

    public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock) => NTStatus.STATUS_NOT_SUPPORTED;

    public NTStatus UnlockFile(object handle, long byteOffset, long length) => NTStatus.STATUS_NOT_SUPPORTED;

    public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName, FileInformationClass informationClass) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }

    public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
    {
        result = GetFileInformationStatus == NTStatus.STATUS_SUCCESS ? new FileNetworkOpenInformation() : null;
        return GetFileInformationStatus;
    }

    public NTStatus SetFileInformation(object handle, FileInformation information) => NTStatus.STATUS_NOT_SUPPORTED;

    public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }

    public NTStatus SetFileSystemInformation(FileSystemInformation information) => NTStatus.STATUS_NOT_SUPPORTED;

    public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation) { result = null; return NTStatus.STATUS_NOT_SUPPORTED; }

    public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor) => NTStatus.STATUS_NOT_SUPPORTED;

    public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
    {
        ioRequest = null;
        return NotifyChangeStatus;
    }

    public NTStatus Cancel(object ioRequest) => NTStatus.STATUS_SUCCESS;

    public NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength)
    {
        output = new byte[0];
        return DeviceIOControlStatus;
    }
}

internal class StubShare : ISMBShare
{
    public StubShare(INTFileStore store) { FileStore = store; }

    public string Name => "IPC$";

    public INTFileStore FileStore { get; }
}

internal static class Smb1Internals
{
    internal static readonly Assembly Library = typeof(SMB2Client).Assembly;
    private const BindingFlags Flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance;

    internal static object CreateState()
    {
        object baseState = Activator.CreateInstance(Library.GetType("SMBLibrary.Server.ConnectionState"), new object[] { null, null, null });
        object state = Activator.CreateInstance(Library.GetType("SMBLibrary.Server.SMB1ConnectionState"), new object[] { baseState });
        state.GetType().GetField("MaxBufferSize").SetValue(state, 4356);
        return state;
    }

    internal static object CreateSession(object state)
    {
        return Call(state, "CreateSession", (ushort)1, "user", "machine", new byte[16], null);
    }

    internal static object Static(string typeName, string method, params object[] args)
    {
        Type type = Library.GetType(typeName);
        MethodInfo target = type.GetMethods(Flags).Single(m => m.Name == method && Matches(m, args));
        return Unwrap(() => target.Invoke(null, args));
    }

    internal static object Call(object instance, string method, params object[] args)
    {
        MethodInfo target = instance.GetType().GetMethods(Flags).Single(m => m.Name == method && Matches(m, args));
        return Unwrap(() => target.Invoke(instance, args));
    }

    private static bool Matches(MethodInfo method, object[] args)
    {
        ParameterInfo[] parameters = method.GetParameters();
        if (parameters.Length != args.Length)
        {
            return false;
        }
        for (int index = 0; index < args.Length; index++)
        {
            Type parameterType = parameters[index].ParameterType;
            if (parameterType.IsByRef)
            {
                parameterType = parameterType.GetElementType();
            }
            if (args[index] != null && !parameterType.IsInstanceOfType(args[index]))
            {
                return false;
            }
        }
        return true;
    }

    private static object Unwrap(Func<object> call)
    {
        try
        {
            return call();
        }
        catch (TargetInvocationException ex)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }
    }
}

public class NotifyChangeHelperTests
{
    private const string Helper = "SMBLibrary.Server.SMB1.NotifyChangeHelper";

    [Fact]
    public void NotifyChange_OnAnUnknownFid_ReturnsInvalidHandle()
    {
        object state = Smb1Internals.CreateState();
        Smb1Internals.CreateSession(state);
        SMB1Header header = new SMB1Header { UID = 1, TID = 1, PID = 2, MID = 3 };
        NTTransactNotifyChangeRequest request = new NTTransactNotifyChangeRequest { FID = 99 };

        Exception error = Record.Exception(() => Smb1Internals.Static(Helper, "ProcessNTTransactNotifyChangeRequest", header, 0u, request, new StubShare(new StubFileStore()), state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_INVALID_HANDLE, header.Status);
    }

    [Fact]
    public void NotifyChange_ThatDoesNotGoPending_LeavesNoPendingRequest()
    {
        object state = Smb1Internals.CreateState();
        object session = Smb1Internals.CreateSession(state);
        ushort fid = (ushort)Smb1Internals.Call(session, "AddOpenFile", (ushort)1, "IPC$", "srvsvc", new object(), FileAccess.Read);
        SMB1Header header = new SMB1Header { UID = 1, TID = 1, PID = 2, MID = 3 };
        NTTransactNotifyChangeRequest request = new NTTransactNotifyChangeRequest { FID = fid };

        Smb1Internals.Static(Helper, "ProcessNTTransactNotifyChangeRequest", header, 0u, request, new StubShare(new StubFileStore()), state);

        Assert.Null(Smb1Internals.Call(state, "GetAsyncContext", (ushort)1, (ushort)1, 2u, (ushort)3));
    }
}

public class QueryInformationTests
{
    [Fact]
    public void QueryInformation_WhenTheStoreFailsTheQuery_ReturnsThatStatus()
    {
        StubFileStore store = new StubFileStore { GetFileInformationStatus = NTStatus.STATUS_ACCESS_DENIED };
        object[] args = { null, store, "file.txt", null };

        object status = Smb1Internals.Static("SMBLibrary.Server.SMB1.SMB1FileStoreHelper", "QueryInformation", args);

        Assert.Equal(NTStatus.STATUS_ACCESS_DENIED, status);
    }
}

public class TransactionWaitNamedPipeTests
{
    private const string TransactionHelper = "SMBLibrary.Server.SMB1.TransactionHelper";
    private const string SubcommandHelper = "SMBLibrary.Server.SMB1.TransactionSubcommandHelper";

    [Fact]
    public void WaitNamedPipe_OnAKnownPipe_ReturnsAnEmptySuccessResponse()
    {
        object state = Smb1Internals.CreateState();
        SMB1Header header = new SMB1Header { PID = 4 };
        byte[] setup = new TransactionWaitNamedPipeRequest().GetSetup();

        object response = null;
        Exception error = Record.Exception(() => response = Smb1Internals.Static(TransactionHelper, "GetCompleteTransactionResponse",
            header, 0u, 0u, @"\PIPE\srvsvc", setup, new byte[0], new byte[0], new StubShare(new StubFileStore()), state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_SUCCESS, header.Status);
        Assert.Single((List<SMB1Command>)response);
    }

    [Theory]
    [InlineData("x")]
    [InlineData(@"\TMP\srvsvc")]
    public void WaitNamedPipe_WithAnInvalidName_ReturnsInvalidSmb(string name)
    {
        object state = Smb1Internals.CreateState();
        SMB1Header header = new SMB1Header();
        TransactionWaitNamedPipeRequest request = new TransactionWaitNamedPipeRequest();

        Exception error = Record.Exception(() => Smb1Internals.Static(SubcommandHelper, "ProcessSubcommand",
            header, 0u, name, request, new StubShare(new StubFileStore()), state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_INVALID_SMB, header.Status);
    }
}

public class TransactionSecondaryTests
{
    private const string TransactionHelper = "SMBLibrary.Server.SMB1.TransactionHelper";

    private static List<SMB1Command> Invoke(SMB1Header header, TransactionSecondaryRequest request, object state)
    {
        return (List<SMB1Command>)Smb1Internals.Static(TransactionHelper, "GetTransactionResponse", header, request, new StubShare(new StubFileStore()), state);
    }

    [Fact]
    public void SecondaryRequest_WithoutAFirstRequest_ReturnsAnErrorStatus()
    {
        object state = Smb1Internals.CreateState();
        SMB1Header header = new SMB1Header { PID = 5 };
        TransactionSecondaryRequest secondary = new TransactionSecondaryRequest { TransParameters = new byte[0], TransData = new byte[4] };

        Exception error = Record.Exception(() => Invoke(header, secondary, state));

        Assert.Null(error);
        Assert.NotEqual(NTStatus.STATUS_SUCCESS, header.Status);
    }

    [Fact]
    public void SecondaryRequest_WithADisplacementBeyondTheBuffer_ReturnsAnErrorStatus()
    {
        object state = Smb1Internals.CreateState();
        SMB1Header header = new SMB1Header { PID = 6 };
        TransactionRequest first = new TransactionRequest
        {
            TotalParameterCount = 0,
            TotalDataCount = 10,
            Setup = new byte[0],
            Name = @"\PIPE\srvsvc",
            TransParameters = new byte[0],
            TransData = new byte[0],
        };
        Smb1Internals.Static(TransactionHelper, "GetTransactionResponse", header, first, new StubShare(new StubFileStore()), state);
        TransactionSecondaryRequest secondary = new TransactionSecondaryRequest
        {
            DataDisplacement = 100,
            TransParameters = new byte[0],
            TransData = new byte[4],
        };

        Exception error = Record.Exception(() => Invoke(header, secondary, state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_INVALID_PARAMETER, header.Status);
    }
}
