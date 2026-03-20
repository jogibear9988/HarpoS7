using HarpoS7.PoC.Protocol;

namespace HarpoS7.Tests.Protocol;

[TestFixture]
public class S7CommPlusHeaderTests
{
    [Test]
    public void Parse_ValidConnectHeader_ReturnsCorrectValues()
    {
        // Header from a CreateObject request: 72 01 01 01
        byte[] data = [0x72, 0x01, 0x01, 0x01];
        var header = S7CommPlusHeader.Parse(data);

        Assert.That(header.PduType, Is.EqualTo(S7CommPlusConstants.PduTypeConnect));
        Assert.That(header.DataLength, Is.EqualTo(0x0101));
    }

    [Test]
    public void Parse_ValidDataHeader_ReturnsCorrectValues()
    {
        // Header from a SetMultiVars request: 72 02 01 77
        byte[] data = [0x72, 0x02, 0x01, 0x77];
        var header = S7CommPlusHeader.Parse(data);

        Assert.That(header.PduType, Is.EqualTo(S7CommPlusConstants.PduTypeData));
        Assert.That(header.DataLength, Is.EqualTo(0x0177));
    }

    [Test]
    public void Parse_ValidIntegrityHeader_ReturnsCorrectValues()
    {
        // Header from a GetVarSubStreamed: 72 03 00 56
        byte[] data = [0x72, 0x03, 0x00, 0x56];
        var header = S7CommPlusHeader.Parse(data);

        Assert.That(header.PduType, Is.EqualTo(S7CommPlusConstants.PduTypeDataWithIntegrity));
        Assert.That(header.DataLength, Is.EqualTo(0x0056));
    }

    [Test]
    public void Parse_InvalidProtocolId_ThrowsException()
    {
        byte[] data = [0x71, 0x01, 0x00, 0x10]; // wrong protocol ID
        Assert.Throws<InvalidDataException>(() => S7CommPlusHeader.Parse(data));
    }

    [Test]
    public void Parse_TooShort_ThrowsException()
    {
        byte[] data = [0x72, 0x01]; // only 2 bytes
        Assert.Throws<ArgumentException>(() => S7CommPlusHeader.Parse(data));
    }

    [Test]
    public void WriteTo_ProducesCorrectBytes()
    {
        var header = new S7CommPlusHeader
        {
            PduType = S7CommPlusConstants.PduTypeData,
            DataLength = 0x0177
        };

        Span<byte> buffer = stackalloc byte[4];
        header.WriteTo(buffer);

        Assert.That(buffer[0], Is.EqualTo(S7CommPlusConstants.ProtocolId));
        Assert.That(buffer[1], Is.EqualTo(0x02));
        Assert.That(buffer[2], Is.EqualTo(0x01));
        Assert.That(buffer[3], Is.EqualTo(0x77));
    }

    [Test]
    public void WriteTrailerTo_ProducesCorrectBytes()
    {
        var header = new S7CommPlusHeader
        {
            PduType = S7CommPlusConstants.PduTypeConnect,
            DataLength = 100
        };

        Span<byte> buffer = stackalloc byte[4];
        header.WriteTrailerTo(buffer);

        Assert.That(buffer[0], Is.EqualTo(S7CommPlusConstants.ProtocolId));
        Assert.That(buffer[1], Is.EqualTo(S7CommPlusConstants.PduTypeConnect));
        Assert.That(buffer[2], Is.EqualTo(0x00));
        Assert.That(buffer[3], Is.EqualTo(0x00));
    }

    [Test]
    public void RoundTrip_ParseWriteParse_Identical()
    {
        var original = new S7CommPlusHeader
        {
            PduType = S7CommPlusConstants.PduTypeDataWithIntegrity,
            DataLength = 339
        };

        byte[] buffer = new byte[4];
        original.WriteTo(buffer);

        var parsed = S7CommPlusHeader.Parse(buffer);
        Assert.That(parsed.PduType, Is.EqualTo(original.PduType));
        Assert.That(parsed.DataLength, Is.EqualTo(original.DataLength));
    }
}
