using HarpoS7.PoC.Packets;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.Tests.Protocol;

[TestFixture]
public class CreateObjectRequestTests
{
    [Test]
    public void BuildPayload_HasCorrectProtocolHeader()
    {
        var request = new CreateObjectRequest();
        var payload = request.BuildPayload();

        // First bytes should be S7CommPlus header
        Assert.That(payload[0], Is.EqualTo(S7CommPlusConstants.ProtocolId)); // 0x72
        Assert.That(payload[1], Is.EqualTo(S7CommPlusConstants.PduTypeConnect)); // 0x01
    }

    [Test]
    public void BuildPayload_HasCorrectTrailer()
    {
        var request = new CreateObjectRequest();
        var payload = request.BuildPayload();

        // Last 4 bytes should be trailer
        Assert.That(payload[^4], Is.EqualTo(S7CommPlusConstants.ProtocolId)); // 0x72
        Assert.That(payload[^3], Is.EqualTo(S7CommPlusConstants.PduTypeConnect)); // 0x01
        Assert.That(payload[^2], Is.EqualTo(0x00));
        Assert.That(payload[^1], Is.EqualTo(0x00));
    }

    [Test]
    public void BuildPayload_HasCorrectOpcodeHeader()
    {
        var request = new CreateObjectRequest();
        var payload = request.BuildPayload();

        // Opcode header starts at offset 4 (after S7CommPlus header)
        Assert.That(payload[4], Is.EqualTo(S7CommPlusConstants.OpcodeRequest)); // 0x31
        // Reserved bytes
        Assert.That(payload[5], Is.EqualTo(0x00));
        Assert.That(payload[6], Is.EqualTo(0x00));
        // Function code: CreateObject (0x04CA)
        Assert.That(payload[7], Is.EqualTo(0x04));
        Assert.That(payload[8], Is.EqualTo(0xCA));
    }

    [Test]
    public void BuildPayload_ContainsSessionName()
    {
        var request = new CreateObjectRequest { SessionName = "TestSession_123" };
        var payload = request.BuildPayload();
        var payloadString = System.Text.Encoding.UTF8.GetString(payload);

        Assert.That(payloadString, Does.Contain("TestSession_123"));
    }

    [Test]
    public void BuildPayload_ContainsHostName()
    {
        var request = new CreateObjectRequest { HostName = "MyTestHost" };
        var payload = request.BuildPayload();
        var payloadString = System.Text.Encoding.UTF8.GetString(payload);

        Assert.That(payloadString, Does.Contain("MyTestHost"));
    }

    [Test]
    public void BuildPayload_ContainsSubscriptionContainer()
    {
        var request = new CreateObjectRequest();
        var payload = request.BuildPayload();
        var payloadString = System.Text.Encoding.UTF8.GetString(payload);

        Assert.That(payloadString, Does.Contain("SubscriptionContainer"));
    }

    [Test]
    public void BuildPayload_DataLengthMatchesContent()
    {
        var request = new CreateObjectRequest();
        var payload = request.BuildPayload();

        // Parse the data length from the header
        var header = S7CommPlusHeader.Parse(payload);
        var expectedTotalLength = S7CommPlusConstants.HeaderLength + header.DataLength + S7CommPlusConstants.TrailerLength;

        Assert.That(payload.Length, Is.EqualTo(expectedTotalLength));
    }

    [Test]
    public void BuildPayload_ContainsStartOfObjectTags()
    {
        var request = new CreateObjectRequest();
        var payload = request.BuildPayload();

        // Should contain at least 2 StartOfObject tags (0xA1)
        var startOfObjectCount = payload.Count(b => b == S7CommPlusConstants.TagStartOfObject);
        Assert.That(startOfObjectCount, Is.GreaterThanOrEqualTo(2));
    }

    [Test]
    public void BuildPayload_ContainsEndOfObjectTags()
    {
        var request = new CreateObjectRequest();
        var payload = request.BuildPayload();

        // Should contain EndOfObject tags (0xA2)
        var endOfObjectCount = payload.Count(b => b == S7CommPlusConstants.TagEndOfObject);
        Assert.That(endOfObjectCount, Is.GreaterThanOrEqualTo(2));
    }

    [Test]
    public void WriteTo_WritesToStream()
    {
        var request = new CreateObjectRequest();
        using var ms = new MemoryStream();

        request.WriteTo(ms);

        Assert.That(ms.Length, Is.GreaterThan(0));
        ms.Position = 0;
        Assert.That(ms.ReadByte(), Is.EqualTo(S7CommPlusConstants.ProtocolId));
    }
}
