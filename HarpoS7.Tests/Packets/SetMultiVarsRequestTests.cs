using HarpoS7.Packets;
using HarpoS7.Utilities.Auth;

namespace HarpoS7.Tests.Packets;

[TestFixture]
public class SetMultiVarsRequestTests
{
    [Test]
    public void Serialize_S71200_ProducesValidS7CommPlusPacket()
    {
        // Arrange: use the same key IDs that were in the original S71200 template
        var publicKeyId = new byte[8];
        var symmetricKeyId = new byte[8];
        // Generate some test key IDs (8 bytes each)
        publicKeyId.AsSpan().Fill(0x33);
        symmetricKeyId.AsSpan().Fill(0x44);
        
        // Create a test blob (180 bytes for real PLC)
        var blobData = new byte[CommonConstants.EncryptedBlobLengthRealPlc];
        blobData.AsSpan().Fill(0xAA);
        
        uint sessionId = 0x12345678;
        
        // Act
        var packet = SetMultiVarsRequest.Serialize(
            sessionId, publicKeyId, symmetricKeyId, blobData, EPublicKeyFamily.S71200);
        
        // Assert: basic structure checks
        Assert.That(packet, Is.Not.Null);
        Assert.That(packet.Length, Is.GreaterThan(8)); // At least header + trailer
        
        // S7CommPlus magic
        Assert.That(packet[0], Is.EqualTo(0x72));
        // Opcode
        Assert.That(packet[1], Is.EqualTo(0x02));
        
        // Trailer
        Assert.That(packet[^4], Is.EqualTo(0x72));
        Assert.That(packet[^3], Is.EqualTo(0x02));
        Assert.That(packet[^2], Is.EqualTo(0x00));
        Assert.That(packet[^1], Is.EqualTo(0x00));
        
        // Data length in header should match actual data
        var dataLength = (packet[2] << 8) | packet[3];
        Assert.That(dataLength, Is.EqualTo(packet.Length - 8)); // total - header(4) - trailer(4)
        
        // Session ID should appear in the packet (big-endian)
        var sessionIdBytes = new byte[] { 0x12, 0x34, 0x56, 0x78 };
        Assert.That(ContainsSequence(packet, sessionIdBytes), Is.True, "Packet should contain session ID");
        
        // Blob data should appear in the packet
        Assert.That(ContainsSequence(packet, new byte[] { 0xAA, 0xAA, 0xAA, 0xAA }), Is.True, 
            "Packet should contain blob data");
    }
    
    [Test]
    public void Serialize_S71500_ProducesValidS7CommPlusPacket()
    {
        var publicKeyId = new byte[8];
        var symmetricKeyId = new byte[8];
        publicKeyId.AsSpan().Fill(0x11);
        symmetricKeyId.AsSpan().Fill(0x22);
        
        var blobData = new byte[CommonConstants.EncryptedBlobLengthRealPlc];
        blobData.AsSpan().Fill(0xBB);
        
        uint sessionId = 0xAABBCCDD;
        
        var packet = SetMultiVarsRequest.Serialize(
            sessionId, publicKeyId, symmetricKeyId, blobData, EPublicKeyFamily.S71500);
        
        Assert.That(packet[0], Is.EqualTo(0x72));
        Assert.That(packet[1], Is.EqualTo(0x02));
        Assert.That(packet[^4], Is.EqualTo(0x72));
        Assert.That(packet[^3], Is.EqualTo(0x02));
        
        var dataLength = (packet[2] << 8) | packet[3];
        Assert.That(dataLength, Is.EqualTo(packet.Length - 8));
    }
    
    [Test]
    public void Serialize_PlcSim_ProducesValidS7CommPlusPacket()
    {
        var publicKeyId = new byte[8];
        var symmetricKeyId = new byte[8];
        publicKeyId.AsSpan().Fill(0x55);
        symmetricKeyId.AsSpan().Fill(0x66);
        
        var blobData = new byte[CommonConstants.EncryptedBlobLengthPlcSim];
        blobData.AsSpan().Fill(0xCC);
        
        uint sessionId = 0x11223344;
        
        var packet = SetMultiVarsRequest.Serialize(
            sessionId, publicKeyId, symmetricKeyId, blobData, EPublicKeyFamily.PlcSim);
        
        Assert.That(packet[0], Is.EqualTo(0x72));
        Assert.That(packet[1], Is.EqualTo(0x02));
        Assert.That(packet[^4], Is.EqualTo(0x72));
        Assert.That(packet[^3], Is.EqualTo(0x02));
        
        var dataLength = (packet[2] << 8) | packet[3];
        Assert.That(dataLength, Is.EqualTo(packet.Length - 8));
    }
    
    [Test]
    public void Serialize_ContainsFunctionHeader()
    {
        var publicKeyId = new byte[8];
        var symmetricKeyId = new byte[8];
        var blobData = new byte[CommonConstants.EncryptedBlobLengthRealPlc];
        
        var packet = SetMultiVarsRequest.Serialize(
            0x1234, publicKeyId, symmetricKeyId, blobData, EPublicKeyFamily.S71500);
        
        // Function header starts at byte 4 (after S7+ header)
        Assert.That(packet[4], Is.EqualTo(0x31)); // Function/sequence ID
        Assert.That(packet[5], Is.EqualTo(0x00));
        Assert.That(packet[6], Is.EqualTo(0x00));
        Assert.That(packet[7], Is.EqualTo(0x05));
        Assert.That(packet[8], Is.EqualTo(0x42));
    }
    
    [Test]
    public void Serialize_SessionIdAppearsInCorrectPositions()
    {
        var publicKeyId = new byte[8];
        var symmetricKeyId = new byte[8];
        var blobData = new byte[CommonConstants.EncryptedBlobLengthRealPlc];
        uint sessionId = 0xDEADBEEF;
        
        var packet = SetMultiVarsRequest.Serialize(
            sessionId, publicKeyId, symmetricKeyId, blobData, EPublicKeyFamily.S71500);
        
        // Session ID 1 starts at offset 4 + 9 = 13 (after S7+ header + function header)
        Assert.That(packet[13], Is.EqualTo(0xDE));
        Assert.That(packet[14], Is.EqualTo(0xAD));
        Assert.That(packet[15], Is.EqualTo(0xBE));
        Assert.That(packet[16], Is.EqualTo(0xEF));
        
        // Separator
        Assert.That(packet[17], Is.EqualTo(0x34));
        
        // Session ID 2
        Assert.That(packet[18], Is.EqualTo(0xDE));
        Assert.That(packet[19], Is.EqualTo(0xAD));
        Assert.That(packet[20], Is.EqualTo(0xBE));
        Assert.That(packet[21], Is.EqualTo(0xEF));
    }

    private static bool ContainsSequence(byte[] data, byte[] sequence)
    {
        for (int i = 0; i <= data.Length - sequence.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < sequence.Length; j++)
            {
                if (data[i + j] != sequence[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
}
