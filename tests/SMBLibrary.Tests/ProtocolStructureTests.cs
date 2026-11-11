using SMBLibrary;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.NetBios;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;
using Xunit;

namespace SMBLibrary.Tests;

public class AVPairKeyTests
{
    [Fact]
    public void Timestamp_IsTheMsvAvTimestampKey_AndDiffersFromFlags()
    {
        Assert.Equal((ushort)7, (ushort)AVPairKey.Timestamp);
        Assert.NotEqual(AVPairKey.Flags, AVPairKey.Timestamp);
    }
}

public class FileFsObjectIdInformationTests
{
    [Fact]
    public void Parse_KeepsTheObjectIdFromTheBuffer()
    {
        Guid id = new Guid("00000000-0000-4000-8000-000000000001");
        FileFsObjectIdInformation written = new FileFsObjectIdInformation { ObjectID = id };
        byte[] buffer = new byte[FileFsObjectIdInformation.FixedLength];
        written.WriteBytes(buffer, 0);

        FileFsObjectIdInformation parsed = new FileFsObjectIdInformation(buffer, 0);

        Assert.Equal(id, parsed.ObjectID);
    }
}

public class NodeStatisticsTests
{
    [Fact]
    public void Parse_RoundTripsEveryCounter()
    {
        NodeStatistics stats = new NodeStatistics
        {
            Jumpers = 1,
            TestResult = 2,
            VersionNumber = 3,
            NumberOfSendAborts = 6,
            NumberOfGoodSends = 0x01020304,
            NumberOfGoodReceives = 0x05060708,
            NumberOfRetransmits = 9,
            SessionDataPacketSize = 19,
        };
        byte[] bytes = stats.GetBytes();
        int offset = 0;

        NodeStatistics parsed = new NodeStatistics(bytes, ref offset);

        Assert.Equal(NodeStatistics.Length, offset);
        Assert.Equal(0x01020304u, parsed.NumberOfGoodSends);
        Assert.Equal(0x05060708u, parsed.NumberOfGoodReceives);
        Assert.Equal((ushort)9, parsed.NumberOfRetransmits);
        Assert.Equal((ushort)19, parsed.SessionDataPacketSize);
    }
}

public class NameFlagsTests
{
    [Fact]
    public void MNode_RoundTripsThroughTheUShort()
    {
        NameFlags flags = new NameFlags { NodeType = OwnerNodeType.MNode, WorkGroup = true };

        ushort value = (ushort)flags;
        NameFlags parsed = (NameFlags)value;

        Assert.Equal(0x4000, value & 0x6000);
        Assert.Equal(OwnerNodeType.MNode, parsed.NodeType);
        Assert.True(parsed.WorkGroup);
    }
}

public class NTTransactResponseTests
{
    [Fact]
    public void Parse_ReadsSetupFromAfterTheSetupCountByte()
    {
        NTTransactResponse response = new NTTransactResponse
        {
            Setup = new byte[] { 0x34, 0x12 },
            TransParameters = new byte[] { 1, 2, 3, 4 },
            TransData = new byte[] { 5, 6, 7, 8 },
        };
        SMB1Message message = new SMB1Message();
        message.Header.Flags |= HeaderFlags.Reply;
        message.Commands.Add(response);

        SMB1Message parsed = new SMB1Message(message.GetBytes());

        NTTransactResponse result = Assert.IsType<NTTransactResponse>(parsed.Commands[0]);
        Assert.Equal(new byte[] { 0x34, 0x12 }, result.Setup);
    }
}

public class LockingAndXRequestTests
{
    [Fact]
    public void GetBytes_RoundTripsUnlocksAndLocks()
    {
        LockingAndXRequest request = new LockingAndXRequest { FID = 5, Timeout = 1000 };
        request.Unlocks.Add(new LockingRange { PID = 1, ByteOffset = 10, LengthInBytes = 20 });
        request.Locks.Add(new LockingRange { PID = 2, ByteOffset = 30, LengthInBytes = 40 });
        request.Locks.Add(new LockingRange { PID = 3, ByteOffset = 50, LengthInBytes = 60 });
        SMB1Message message = new SMB1Message();
        message.Commands.Add(request);

        SMB1Message parsed = new SMB1Message(message.GetBytes());

        LockingAndXRequest result = Assert.IsType<LockingAndXRequest>(parsed.Commands[0]);
        Assert.Single(result.Unlocks);
        Assert.Equal(2, result.Locks.Count);
        Assert.Equal(60ul, result.Locks[1].LengthInBytes);
    }
}

public class NamedPipeStatusTests
{
    [Fact]
    public void ParseFromUShort_ReadsTheNonBlockingBit()
    {
        NamedPipeStatus status = new NamedPipeStatus((ushort)0x8000);

        Assert.Equal(NonBlocking.DoNotBlock, status.NonBlocking);
    }
}

public class SMB1HelperTests
{
    [Fact]
    public void ReadNullableFileTime_ReturnsNullForZero()
    {
        DateTime? result = SMB1Helper.ReadNullableFileTime(new byte[8], 0);

        Assert.Null(result);
    }
}

public class LockElementTests
{
    [Fact]
    public void WriteBytes_StaysInsideTheElementAndRoundTrips()
    {
        LockElement element = new LockElement
        {
            Offset = 1,
            Length = 2,
            Flags = LockFlags.ExclusiveLock,
            Reserved = 0,
        };
        byte[] buffer = new byte[LockElement.StructureLength];

        element.WriteBytes(buffer, 0);
        LockElement parsed = new LockElement(buffer, 0);

        Assert.Equal(1ul, parsed.Offset);
        Assert.Equal(2ul, parsed.Length);
        Assert.Equal(LockFlags.ExclusiveLock, parsed.Flags);
    }
}
