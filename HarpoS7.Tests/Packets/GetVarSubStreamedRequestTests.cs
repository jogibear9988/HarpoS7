using HarpoS7.Packets;

namespace HarpoS7.Tests.Packets;

[TestFixture]
public class GetVarSubStreamedRequestTests
{
    [Test]
    public void Serialize_ProducesValidS7CommPlusPacket()
    {
        var sessionKey = new byte[Constants.SessionKeyLength];
        sessionKey.AsSpan().Fill(0x33);
        uint sessionId = 0xAABBCCDD;
        
        var packet = GetVarSubStreamedRequest.Serialize(sessionKey, sessionId);
        
        Assert.That(packet, Is.Not.Null);
        Assert.That(packet.Length, Is.GreaterThan(8));
        
        // S7CommPlus magic
        Assert.That(packet[0], Is.EqualTo(0x72));
        // Opcode 0x03
        Assert.That(packet[1], Is.EqualTo(0x03));
        
        // Trailer
        Assert.That(packet[^4], Is.EqualTo(0x72));
        Assert.That(packet[^3], Is.EqualTo(0x03));
        Assert.That(packet[^2], Is.EqualTo(0x00));
        Assert.That(packet[^1], Is.EqualTo(0x00));
        
        // Data length
        var dataLength = (packet[2] << 8) | packet[3];
        Assert.That(dataLength, Is.EqualTo(packet.Length - 8));
    }
    
    [Test]
    public void Serialize_ContainsNonZeroDigest()
    {
        var sessionKey = new byte[Constants.SessionKeyLength];
        sessionKey.AsSpan().Fill(0x42);
        uint sessionId = 0x12345678;
        
        var packet = GetVarSubStreamedRequest.Serialize(sessionKey, sessionId);
        
        // Digest starts at data byte 1 (offset 5 in full packet: header(4) + marker(1))
        // At least some digest bytes should be non-zero
        var hasNonZero = false;
        for (int i = 5; i < 5 + 32; i++)
        {
            if (packet[i] != 0)
            {
                hasNonZero = true;
                break;
            }
        }
        Assert.That(hasNonZero, Is.True, "Digest should contain non-zero bytes");
    }
}
