using System.Security.Cryptography;
using SMBLibrary;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;
using Utilities;
using Xunit;
using AesCcm = Utilities.AesCcm;
using ReadRequest = SMBLibrary.SMB1.ReadRequest;

namespace SMBLibrary.Tests;

public class AesCcmTagTests
{
    private static readonly byte[] Key = new byte[16];
    private static readonly byte[] Nonce = new byte[11];

    [Fact]
    public void DecryptAndAuthenticate_AcceptsTheRightTag_AndRejectsAWrongOne()
    {
        byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        byte[] aad = new byte[] { 9, 8, 7 };
        byte[] encrypted = AesCcm.Encrypt(Key, Nonce, data, aad, 16, out byte[] tag);

        byte[] decrypted = AesCcm.DecryptAndAuthenticate(Key, Nonce, encrypted, aad, tag);
        Assert.Equal(data, decrypted);

        byte[] wrongLast = (byte[])tag.Clone();
        wrongLast[15] ^= 0x01;
        Assert.Throws<CryptographicException>(() => AesCcm.DecryptAndAuthenticate(Key, Nonce, encrypted, aad, wrongLast));
        byte[] wrongFirst = (byte[])tag.Clone();
        wrongFirst[0] ^= 0x80;
        Assert.Throws<CryptographicException>(() => AesCcm.DecryptAndAuthenticate(Key, Nonce, encrypted, aad, wrongFirst));
    }
}

public class SMB1MessageChainTests
{
    [Fact(Timeout = 5000)]
    public async Task SelfPointingAndXOffset_IsRejected()
    {
        byte[] header = new SMB1Header { Command = CommandName.SMB_COM_LOGOFF_ANDX }.GetBytes();
        byte[] command = new byte[] { 2, (byte)CommandName.SMB_COM_LOGOFF_ANDX, 0, SMB1Header.Length, 0, 0, 0 };
        byte[] message = header.Concat(command).ToArray();

        Task<Exception> run = Task.Run(() => Record.Exception(() => new SMB1Message(message)));
        Task finished = await Task.WhenAny(run, Task.Delay(1000));

        Assert.Same(run, finished);
        Assert.IsType<InvalidDataException>(await run);
    }
}

public class QueryDirectoryListTests
{
    [Fact(Timeout = 5000)]
    public async Task ReadFileInformationList_RejectsBackwardOffsets()
    {
        byte[] buffer = new byte[48];
        BitConverter.GetBytes(16u).CopyTo(buffer, 0);
        BitConverter.GetBytes(unchecked((uint)-16)).CopyTo(buffer, 16);

        Task<Exception> run = Task.Run(() => Record.Exception(() =>
            QueryDirectoryFileInformation.ReadFileInformationList(buffer, 0, FileInformationClass.FileNamesInformation)));
        Task finished = await Task.WhenAny(run, Task.Delay(1000));

        Assert.Same(run, finished);
        Assert.NotNull(await run);
    }
}

public class SMB1CommandParsingTests
{
    [Fact]
    public void ReadRequest_KeepsCountAndRemainingEstimateApart()
    {
        ReadRequest request = new ReadRequest { FID = 5, CountOfBytesToRead = 100, ReadOffsetInBytes = 4096, EstimateOfRemainingBytesToBeRead = 7 };
        byte[] bytes = request.GetBytes(false);

        ReadRequest parsed = new ReadRequest(bytes, 0);

        Assert.Equal((ushort)100, parsed.CountOfBytesToRead);
        Assert.Equal((ushort)7, parsed.EstimateOfRemainingBytesToBeRead);
    }

    [Fact]
    public void QueryInformationDiskResponse_RoundTripsThroughReadCommandResponse()
    {
        QueryInformationDiskResponse response = new QueryInformationDiskResponse { TotalUnits = 10, BlocksPerUnit = 4, BlockSize = 512, FreeUnits = 3 };
        byte[] bytes = response.GetBytes(false);

        SMB1Command parsed = SMB1Command.ReadCommandResponse(bytes, 0, CommandName.SMB_COM_QUERY_INFORMATION_DISK, false);

        QueryInformationDiskResponse disk = Assert.IsType<QueryInformationDiskResponse>(parsed);
        Assert.Equal((ushort)10, disk.TotalUnits);
        Assert.Equal((ushort)3, disk.FreeUnits);
    }

    [Fact]
    public void TransactionSecondaryRequest_ReadsItsHeaderFromTheParameters()
    {
        byte[] message = BuildSecondary(18, includeFid: false);

        TransactionSecondaryRequest parsed = new TransactionSecondaryRequest(message, SMB1Header.Length);

        Assert.Equal((ushort)20, parsed.TotalParameterCount);
        Assert.Equal((ushort)30, parsed.TotalDataCount);
        Assert.Equal((ushort)8, parsed.ParameterDisplacement);
        Assert.Equal((ushort)16, parsed.DataDisplacement);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, parsed.TransParameters);
        Assert.Equal(new byte[] { 5, 6, 7, 8 }, parsed.TransData);
    }

    [Fact]
    public void Transaction2SecondaryRequest_ReadsItsHeaderFromTheParameters()
    {
        byte[] message = BuildSecondary(20, includeFid: true);

        Transaction2SecondaryRequest parsed = new Transaction2SecondaryRequest(message, SMB1Header.Length);

        Assert.Equal((ushort)20, parsed.TotalParameterCount);
        Assert.Equal((ushort)16, parsed.DataDisplacement);
        Assert.Equal((ushort)0x1234, parsed.FID);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, parsed.TransParameters);
        Assert.Equal(new byte[] { 5, 6, 7, 8 }, parsed.TransData);
    }

    // Wire layout: header, WordCount, parameter words, ByteCount, then the payload.
    private static byte[] BuildSecondary(int parametersLength, bool includeFid)
    {
        int parameterOffset = SMB1Header.Length + 1 + parametersLength + 2;
        int dataOffset = parameterOffset + 4;
        byte[] message = new byte[dataOffset + 4];
        int offset = SMB1Header.Length;
        message[offset++] = (byte)(parametersLength / 2);
        foreach (ushort value in new ushort[] { 20, 30, 4, (ushort)parameterOffset, 8, 4, (ushort)dataOffset, 16 })
        {
            BitConverter.GetBytes(value).CopyTo(message, offset);
            offset += 2;
        }
        if (includeFid)
        {
            BitConverter.GetBytes((ushort)0x1234).CopyTo(message, offset);
            offset += 2;
        }
        BitConverter.GetBytes((ushort)8).CopyTo(message, offset);
        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }.CopyTo(message, parameterOffset);
        return message;
    }
}

public class SMB2NegotiateContextTests
{
    [Fact]
    public void EncryptionCapabilities_ParsesTheCiphersTheWriterWrote()
    {
        EncryptionCapabilities written = new EncryptionCapabilities();
        written.Ciphers.Add(CipherAlgorithm.Aes128Gcm);
        written.Ciphers.Add(CipherAlgorithm.Aes128Ccm);
        written.WriteData();
        byte[] buffer = new byte[written.Length];
        written.WriteBytes(buffer, 0);

        EncryptionCapabilities parsed = new EncryptionCapabilities(buffer, 0);

        Assert.Equal(new[] { CipherAlgorithm.Aes128Gcm, CipherAlgorithm.Aes128Ccm }, parsed.Ciphers);
    }
}

public class FindInformationTests
{
    private static readonly string LongName = new string('a', 130);

    [Fact]
    public void FindFileDirectoryInfo_RoundTripsALongUnicodeName()
    {
        FindFileDirectoryInfo written = new FindFileDirectoryInfo { FileName = LongName };
        byte[] buffer = new byte[written.GetLength(true)];
        int offset = 0;
        written.WriteBytes(buffer, ref offset, true);

        FindFileDirectoryInfo parsed = new FindFileDirectoryInfo(buffer, 0, true);

        Assert.Equal(LongName, parsed.FileName);
    }

    [Fact]
    public void FindFileFullDirectoryInfo_RoundTripsALongUnicodeName()
    {
        FindFileFullDirectoryInfo written = new FindFileFullDirectoryInfo { FileName = LongName };
        byte[] buffer = new byte[written.GetLength(true)];
        int offset = 0;
        written.WriteBytes(buffer, ref offset, true);

        FindFileFullDirectoryInfo parsed = new FindFileFullDirectoryInfo(buffer, 0, true);

        Assert.Equal(LongName, parsed.FileName);
    }

    [Fact]
    public void FindFileIDFullDirectoryInfo_RoundTripsALongUnicodeName()
    {
        FindFileIDFullDirectoryInfo written = new FindFileIDFullDirectoryInfo { FileName = LongName };
        byte[] buffer = new byte[written.GetLength(true)];
        int offset = 0;
        written.WriteBytes(buffer, ref offset, true);

        FindFileIDFullDirectoryInfo parsed = new FindFileIDFullDirectoryInfo(buffer, 0, true);

        Assert.Equal(LongName, parsed.FileName);
    }

    [Fact]
    public void FindFileBothDirectoryInfo_RoundTripsALongShortName()
    {
        FindFileBothDirectoryInfo written = new FindFileBothDirectoryInfo { FileName = "file.txt", ShortName = "FILE~1.TXT" };
        byte[] buffer = new byte[written.GetLength(true)];
        int offset = 0;
        written.WriteBytes(buffer, ref offset, true);

        FindFileBothDirectoryInfo parsed = new FindFileBothDirectoryInfo(buffer, 0, true);

        Assert.Equal("FILE~1.TXT", parsed.ShortName);
    }

    [Fact]
    public void FindFileIDBothDirectoryInfo_RoundTripsALongShortName()
    {
        FindFileIDBothDirectoryInfo written = new FindFileIDBothDirectoryInfo { FileName = "file.txt", ShortName = "FILE~1.TXT" };
        byte[] buffer = new byte[written.GetLength(true)];
        int offset = 0;
        written.WriteBytes(buffer, ref offset, true);

        FindFileIDBothDirectoryInfo parsed = new FindFileIDBothDirectoryInfo(buffer, 0, true);

        Assert.Equal("FILE~1.TXT", parsed.ShortName);
    }
}

public class QueryFSVolumeInfoTests
{
    [Fact]
    public void Parse_RoundTripsAVolumeLabel()
    {
        QueryFSVolumeInfo written = new QueryFSVolumeInfo { VolumeLabel = "Media", SerialNumber = 42 };
        byte[] buffer = written.GetBytes(true);

        QueryFSVolumeInfo parsed = new QueryFSVolumeInfo(buffer, 0);

        Assert.Equal("Media", parsed.VolumeLabel);
    }
}

public class CreateRequestTests
{
    [Fact]
    public void Parse_ReadsCreateContextsRelativeToTheCommandOffset()
    {
        CreateRequest request = new CreateRequest { Name = "a.txt" };
        request.CreateContexts.Add(new CreateContext { Name = "MxAc", Data = new byte[8] });
        byte[] command = request.GetBytes();
        byte[] buffer = new byte[64 + command.Length];
        command.CopyTo(buffer, 64);

        CreateRequest parsed = new CreateRequest(buffer, 64);

        Assert.Equal("a.txt", parsed.Name);
        CreateContext context = Assert.Single(parsed.CreateContexts);
        Assert.Equal("MxAc", context.Name);
    }
}
