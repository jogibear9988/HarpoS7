using HarpoS7.PoC.Protocol;

namespace HarpoS7.Tests.Protocol;

[TestFixture]
public class S7CommPlusOpcodeHeaderTests
{
    [Test]
    public void Parse_CreateObjectRequest_ReturnsCorrectValues()
    {
        // From CreateObject request: 31 00 00 04 CA 00 00 00 01
        byte[] data = [0x31, 0x00, 0x00, 0x04, 0xCA, 0x00, 0x00, 0x00, 0x01];
        var header = S7CommPlusOpcodeHeader.Parse(data);

        Assert.That(header.Opcode, Is.EqualTo(S7CommPlusConstants.OpcodeRequest));
        Assert.That(header.Function, Is.EqualTo(S7CommPlusConstants.FunctionCreateObject));
        Assert.That(header.SequenceNumber, Is.EqualTo(1));
    }

    [Test]
    public void Parse_SetMultiVarsRequest_ReturnsCorrectValues()
    {
        // From SetMultiVars request: 31 00 00 05 42 00 00 00 02
        byte[] data = [0x31, 0x00, 0x00, 0x05, 0x42, 0x00, 0x00, 0x00, 0x02];
        var header = S7CommPlusOpcodeHeader.Parse(data);

        Assert.That(header.Opcode, Is.EqualTo(S7CommPlusConstants.OpcodeRequest));
        Assert.That(header.Function, Is.EqualTo(S7CommPlusConstants.FunctionSetMultiVariables));
        Assert.That(header.SequenceNumber, Is.EqualTo(2));
    }

    [Test]
    public void Parse_GetVarSubStreamedRequest_ReturnsCorrectValues()
    {
        // From GetVarSubStreamed request: 31 00 00 05 86 00 00 00 03
        byte[] data = [0x31, 0x00, 0x00, 0x05, 0x86, 0x00, 0x00, 0x00, 0x03];
        var header = S7CommPlusOpcodeHeader.Parse(data);

        Assert.That(header.Opcode, Is.EqualTo(S7CommPlusConstants.OpcodeRequest));
        Assert.That(header.Function, Is.EqualTo(S7CommPlusConstants.FunctionGetVarSubStreamed));
        Assert.That(header.SequenceNumber, Is.EqualTo(3));
    }

    [Test]
    public void Parse_SetVarSubStreamedRequest_ReturnsCorrectValues()
    {
        // From SetVarSubStreamed request: 31 00 00 05 7C 00 00 00 04
        byte[] data = [0x31, 0x00, 0x00, 0x05, 0x7C, 0x00, 0x00, 0x00, 0x04];
        var header = S7CommPlusOpcodeHeader.Parse(data);

        Assert.That(header.Opcode, Is.EqualTo(S7CommPlusConstants.OpcodeRequest));
        Assert.That(header.Function, Is.EqualTo(S7CommPlusConstants.FunctionSetVarSubStreamed));
        Assert.That(header.SequenceNumber, Is.EqualTo(4));
    }

    [Test]
    public void Parse_TooShort_ThrowsException()
    {
        byte[] data = [0x31, 0x00, 0x00];
        Assert.Throws<ArgumentException>(() => S7CommPlusOpcodeHeader.Parse(data));
    }

    [Test]
    public void WriteTo_ProducesCorrectBytes()
    {
        var header = new S7CommPlusOpcodeHeader
        {
            Opcode = S7CommPlusConstants.OpcodeRequest,
            Function = S7CommPlusConstants.FunctionCreateObject,
            SequenceNumber = 1
        };

        byte[] buffer = new byte[S7CommPlusOpcodeHeader.SerializedLength];
        header.WriteTo(buffer);

        Assert.That(buffer[0], Is.EqualTo(0x31)); // opcode
        Assert.That(buffer[1], Is.EqualTo(0x00)); // reserved
        Assert.That(buffer[2], Is.EqualTo(0x00)); // reserved
        Assert.That(buffer[3], Is.EqualTo(0x04)); // function high
        Assert.That(buffer[4], Is.EqualTo(0xCA)); // function low
        Assert.That(buffer[5], Is.EqualTo(0x00)); // reserved
        Assert.That(buffer[6], Is.EqualTo(0x00)); // reserved
        Assert.That(buffer[7], Is.EqualTo(0x00)); // sequence high
        Assert.That(buffer[8], Is.EqualTo(0x01)); // sequence low
    }

    [Test]
    public void RoundTrip_ParseWriteParse_Identical()
    {
        var original = new S7CommPlusOpcodeHeader
        {
            Opcode = S7CommPlusConstants.OpcodeResponse,
            Function = S7CommPlusConstants.FunctionSetMultiVariables,
            SequenceNumber = 42
        };

        byte[] buffer = new byte[S7CommPlusOpcodeHeader.SerializedLength];
        original.WriteTo(buffer);

        var parsed = S7CommPlusOpcodeHeader.Parse(buffer);
        Assert.That(parsed.Opcode, Is.EqualTo(original.Opcode));
        Assert.That(parsed.Function, Is.EqualTo(original.Function));
        Assert.That(parsed.SequenceNumber, Is.EqualTo(original.SequenceNumber));
    }
}
