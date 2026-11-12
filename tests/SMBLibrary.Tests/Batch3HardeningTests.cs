using System.Reflection;
using SMBLibrary;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.Client;
using SMBLibrary.NetBios;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;
using Xunit;

namespace SMBLibrary.Tests;

internal static class RandomSourceInspector
{
    private const BindingFlags AllMethods = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;

    // True when any method body of the type constructs a System.Random.
    internal static bool ConstructsSystemRandom(Type type)
    {
        foreach (MethodBase method in type.GetMethods(AllMethods).Cast<MethodBase>().Concat(type.GetConstructors(AllMethods)))
        {
            byte[] il = method.GetMethodBody()?.GetILAsByteArray();
            if (il == null)
            {
                continue;
            }
            for (int index = 0; index + 4 < il.Length; index++)
            {
                if (il[index] != 0x73) // newobj
                {
                    continue;
                }
                try
                {
                    MethodBase target = type.Module.ResolveMethod(BitConverter.ToInt32(il, index + 1));
                    if (target is ConstructorInfo && target.DeclaringType == typeof(Random))
                    {
                        return true;
                    }
                }
                catch (Exception)
                {
                }
            }
        }
        return false;
    }
}

public class ServerChallengeTests
{
    [Fact]
    public void Challenge_DoesNotUseSystemRandom()
    {
        Assert.False(RandomSourceInspector.ConstructsSystemRandom(typeof(IndependentNTLMAuthenticationProvider)));
    }
}

public class ClientSessionKeyTests
{
    [Fact]
    public void SessionKeyAndClientChallenge_DoNotUseSystemRandom()
    {
        Assert.False(RandomSourceInspector.ConstructsSystemRandom(typeof(NTLMAuthenticationHelper)));
    }
}

public class AesCcmNonceTests
{
    private static readonly Type Cryptography = typeof(SMB2Client).Assembly.GetType("SMBLibrary.SMB2.SMB2Cryptography");

    [Fact]
    public void Nonce_DoesNotUseSystemRandom()
    {
        Assert.False(RandomSourceInspector.ConstructsSystemRandom(Cryptography));
    }

    [Fact]
    public void Nonce_IsUniqueInATightLoop()
    {
        MethodInfo generate = Cryptography.GetMethod("GenerateAesCcmNonce", BindingFlags.NonPublic | BindingFlags.Static);
        HashSet<string> seen = new HashSet<string>();
        for (int index = 0; index < 10000; index++)
        {
            byte[] nonce = (byte[])generate.Invoke(null, null);
            Assert.Equal(11, nonce.Length);
            Assert.True(seen.Add(Convert.ToHexString(nonce)));
        }
    }
}

public class MalformedTokenTests
{
    private class StubMechanism : IGSSMechanism
    {
        public byte[] Identifier => GSSProvider.NTLMSSPIdentifier;

        public NTStatus AcceptSecurityContext(ref object context, byte[] inputToken, out byte[] outputToken)
        {
            outputToken = null;
            return NTStatus.SEC_I_CONTINUE_NEEDED;
        }

        public bool DeleteSecurityContext(ref object context) => true;

        public object GetContextAttribute(object context, GSSAttributeName attributeName) => null;
    }

    private static NTStatus Accept(ref GSSContext context, byte[] token)
    {
        GSSProvider provider = new GSSProvider(new StubMechanism());
        NTStatus status = NTStatus.STATUS_SUCCESS;
        GSSContext local = context;
        Exception error = Record.Exception(() => status = provider.AcceptSecurityContext(ref local, token, out _));
        context = local;
        Assert.Null(error);
        return status;
    }

    [Fact]
    public void ShortRawNtlmToken_IsRejectedAsInvalid()
    {
        GSSContext context = null;
        byte[] token = System.Text.Encoding.ASCII.GetBytes("NTLMSSP\0");

        Assert.Equal(NTStatus.SEC_E_INVALID_TOKEN, Accept(ref context, token));
    }

    [Fact]
    public void NegTokenInitWithoutMechanismList_IsRejectedAsInvalid()
    {
        GSSContext context = null;
        byte[] token = new byte[] { 0x60, 0x11, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x07, 0x30, 0x05, 0xA2, 0x03, 0x04, 0x01, 0x01 };

        Assert.Equal(NTStatus.SEC_E_INVALID_TOKEN, Accept(ref context, token));
    }

    [Fact]
    public void NegTokenRespWithoutResponseToken_IsRejectedAsInvalid()
    {
        GSSContext context = null;
        byte[] init = new SMBLibrary.Authentication.GSSAPI.SimpleProtectedNegotiationTokenInit
        {
            MechanismTypeList = new List<byte[]> { GSSProvider.NTLMSSPIdentifier },
            MechanismToken = new byte[] { 1 },
        }.GetBytes(true);
        Accept(ref context, init);
        Assert.NotNull(context);

        byte[] resp = new byte[] { 0xA1, 0x02, 0x30, 0x00 };

        Assert.Equal(NTStatus.SEC_E_INVALID_TOKEN, Accept(ref context, resp));
    }
}

public class EncryptedSessionResponseTests
{
    [Fact]
    public void PlainResponse_OnAnEncryptedSession_IsDiscarded()
    {
        SMB2Client client = new SMB2Client();
        BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Instance;
        typeof(SMB2Client).GetField("m_dialect", flags).SetValue(client, SMB2Dialect.SMB300);
        typeof(SMB2Client).GetField("m_encryptSessionData", flags).SetValue(client, true);
        typeof(SMB2Client).GetField("m_isLoggedIn", flags).SetValue(client, true);

        SMBLibrary.SMB2.EchoResponse echo = new SMBLibrary.SMB2.EchoResponse();
        echo.Header.MessageID = 1;
        byte[] message = echo.GetBytes();
        SessionMessagePacket packet = new SessionMessagePacket { Trailer = message };
        object state = Activator.CreateInstance(typeof(SMB2Client).Assembly.GetType("SMBLibrary.Client.ConnectionState"), new object[] { null });

        typeof(SMB2Client).GetMethod("ProcessPacket", flags).Invoke(client, new object[] { packet, state });

        System.Collections.IList queue = (System.Collections.IList)typeof(SMB2Client).GetField("m_incomingQueue", flags).GetValue(client);
        Assert.Empty(queue);
    }
}

public class NamedPipeReadTests
{
    [Fact]
    public void ReadFile_RefusesALengthBeyondTheMaximumReadSize()
    {
        NamedPipeStore store = new NamedPipeStore(new List<RemoteService> { new ServerService("TEST", new List<string>()) });
        store.CreateFile(out object handle, out _, @"\srvsvc", 0, 0, 0, 0, 0, null);

        Exception error = Record.Exception(() =>
        {
            NTStatus status = store.ReadFile(out byte[] data, handle, 0, 0x10000000);
            Assert.Equal(NTStatus.STATUS_INVALID_PARAMETER, status);
        });

        Assert.Null(error);
    }
}

public class ExtendedAttributeListTests
{
    [Fact(Timeout = 5000)]
    public async Task ReadList_RejectsOffsetsThatPointBackwards()
    {
        byte[] buffer = new byte[32];
        BitConverter.GetBytes(16u).CopyTo(buffer, 0);
        BitConverter.GetBytes(unchecked((uint)-16)).CopyTo(buffer, 16);

        Task<Exception> run = Task.Run(() => Record.Exception(() => FileFullEAInformation.ReadList(buffer, 0)));
        Task finished = await Task.WhenAny(run, Task.Delay(500));

        Assert.Same(run, finished);
        Assert.NotNull(await run);
    }
}

public class NTTransactSecondaryTests
{
    private static readonly Assembly Library = typeof(SMB2Client).Assembly;

    private static (object helper, object state) CreateState()
    {
        Type connection = Library.GetType("SMBLibrary.Server.ConnectionState");
        object baseState = Activator.CreateInstance(connection, new object[] { null, null, null });
        Type smb1State = Library.GetType("SMBLibrary.Server.SMB1ConnectionState");
        object state = Activator.CreateInstance(smb1State, new object[] { baseState });
        return (Library.GetType("SMBLibrary.Server.SMB1.NTTransactHelper"), state);
    }

    private static object Invoke(object helper, SMB1Header header, SMB1Command request, object state)
    {
        MethodInfo method = ((Type)helper).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(m => m.Name == "GetNTTransactResponse" && m.GetParameters()[1].ParameterType == request.GetType());
        try
        {
            return method.Invoke(null, new object[] { header, request, null, state });
        }
        catch (TargetInvocationException ex)
        {
            throw ex.InnerException;
        }
    }

    private static NTTransactRequest FirstRequest(int dataLength)
    {
        return new NTTransactRequest
        {
            TotalParameterCount = 0,
            TotalDataCount = 10,
            Setup = new byte[0],
            TransParameters = new byte[0],
            TransData = new byte[dataLength],
        };
    }

    [Fact]
    public void SecondaryRequest_WithADisplacementBeyondTheBuffer_ReturnsAnErrorStatus()
    {
        (object helper, object state) = CreateState();
        SMB1Header header = new SMB1Header { PID = 7 };
        Invoke(helper, header, FirstRequest(0), state);

        NTTransactSecondaryRequest secondary = new NTTransactSecondaryRequest
        {
            TotalParameterCount = 0,
            TotalDataCount = 10,
            DataDisplacement = 100,
            TransParameters = new byte[0],
            TransData = new byte[4],
        };
        Exception error = Record.Exception(() => Invoke(helper, header, secondary, state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_INVALID_PARAMETER, header.Status);
    }

    [Fact]
    public void FirstRequest_WithMoreDataThanDeclared_ReturnsAnErrorStatus()
    {
        (object helper, object state) = CreateState();
        SMB1Header header = new SMB1Header { PID = 8 };
        NTTransactRequest request = new NTTransactRequest
        {
            TotalParameterCount = 8,
            TotalDataCount = 4,
            Setup = new byte[0],
            TransParameters = new byte[0],
            TransData = new byte[12],
        };

        Exception error = Record.Exception(() => Invoke(helper, header, request, state));

        Assert.Null(error);
        Assert.Equal(NTStatus.STATUS_INVALID_PARAMETER, header.Status);
    }
}

public class RpcFragmentSizeTests
{
    private class FixedResponseService : RemoteService
    {
        public override Guid InterfaceGuid => Guid.Parse("00000000-0000-4000-8000-000000000001");

        public override string PipeName => "test";

        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes) => new byte[100];
    }

    [Fact(Timeout = 5000)]
    public async Task Response_AfterATinyFragmentSizeBind_Ends()
    {
        RPCPipeStream stream = new RPCPipeStream(new FixedResponseService());
        BindPDU bind = new BindPDU
        {
            Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment,
            DataRepresentation = new DataRepresentationFormat(CharacterFormat.ASCII, ByteOrder.LittleEndian, FloatingPointRepresentation.IEEE),
            MaxTransmitFragmentSize = 24,
            MaxReceiveFragmentSize = 24,
            ContextList = new ContextList(),
        };
        byte[] bindBytes = bind.GetBytes();
        stream.Write(bindBytes, 0, bindBytes.Length);

        RequestPDU request = new RequestPDU
        {
            Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment,
            DataRepresentation = bind.DataRepresentation,
            OpNum = 15,
            Data = new byte[0],
        };
        byte[] requestBytes = request.GetBytes();

        Task<Exception> run = Task.Run(() => Record.Exception(() => stream.Write(requestBytes, 0, requestBytes.Length)));
        Task finished = await Task.WhenAny(run, Task.Delay(500));

        Assert.Same(run, finished);
        Assert.Null(await run);
    }
}
