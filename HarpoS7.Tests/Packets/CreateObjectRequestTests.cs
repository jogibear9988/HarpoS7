using HarpoS7.Packets;

namespace HarpoS7.Tests.Packets;

[TestFixture]
public class CreateObjectRequestTests
{
    [Test]
    public void Serialize_ProducesValidS7CommPlusPacket()
    {
        var packet = CreateObjectRequest.Serialize();
        
        Assert.That(packet, Is.Not.Null);
        Assert.That(packet.Length, Is.GreaterThan(8));
        
        // S7CommPlus magic
        Assert.That(packet[0], Is.EqualTo(0x72));
        // Opcode 0x01 (Request)
        Assert.That(packet[1], Is.EqualTo(0x01));
        
        // Trailer
        Assert.That(packet[^4], Is.EqualTo(0x72));
        Assert.That(packet[^3], Is.EqualTo(0x01));
        Assert.That(packet[^2], Is.EqualTo(0x00));
        Assert.That(packet[^1], Is.EqualTo(0x00));
        
        // Data length
        var dataLength = (packet[2] << 8) | packet[3];
        Assert.That(dataLength, Is.EqualTo(packet.Length - 8));
    }
    
    [Test]
    public void Serialize_IsIdempotent()
    {
        var packet1 = CreateObjectRequest.Serialize();
        var packet2 = CreateObjectRequest.Serialize();
        
        Assert.That(packet1, Is.EqualTo(packet2));
    }
}
