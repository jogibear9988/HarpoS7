namespace HarpoS7.Tests.Packets;

[TestFixture]
public class VlqTests
{
    [Test]
    public void Encode_Zero_ReturnsSingleByte()
    {
        Span<byte> dest = stackalloc byte[9];
        var len = Vlq.Encode(0, dest);
        
        Assert.That(len, Is.EqualTo(1));
        Assert.That(dest[0], Is.EqualTo(0x00));
    }
    
    [Test]
    public void Encode_SmallValue_ReturnsOneByte()
    {
        Span<byte> dest = stackalloc byte[9];
        var len = Vlq.Encode(0x10, dest);
        
        Assert.That(len, Is.EqualTo(1));
        Assert.That(dest[0], Is.EqualTo(0x10));
    }
    
    [Test]
    public void Encode_TwoByte_ReturnsCorrectEncoding()
    {
        Span<byte> dest = stackalloc byte[9];
        // 0x110 = 272
        var len = Vlq.Encode(0x110, dest);
        
        Assert.That(len, Is.EqualTo(2));
        Assert.That(dest[0], Is.EqualTo(0x82));
        Assert.That(dest[1], Is.EqualTo(0x10));
    }
    
    [Test]
    public void RoundTrip_UInt32()
    {
        uint[] values = [0, 1, 127, 128, 256, 0x110, 0x10001, 0xFFFFFFFF];
        var buf = new byte[9];
        
        foreach (var original in values)
        {
            var encLen = Vlq.Encode(original, buf);
            var decoded = Vlq.DecodeUInt32(buf.AsSpan(0, encLen), out var decLen);
            
            Assert.That(decLen, Is.EqualTo(encLen), $"Length mismatch for 0x{original:X}");
            Assert.That(decoded, Is.EqualTo(original), $"Value mismatch for 0x{original:X}");
        }
    }
    
    [Test]
    public void RoundTrip_UInt64()
    {
        ulong[] values = [0, 1, 127, 128, 0x110, 0x10001, 0xFFFFFFFFFFFFFFFF];
        var buf = new byte[9];
        
        foreach (var original in values)
        {
            var encLen = Vlq.Encode(original, buf);
            var decoded = Vlq.DecodeUInt64(buf.AsSpan(0, encLen), out var decLen);
            
            Assert.That(decLen, Is.EqualTo(encLen), $"Length mismatch for 0x{original:X}");
            Assert.That(decoded, Is.EqualTo(original), $"Value mismatch for 0x{original:X}");
        }
    }
    
    [Test]
    public void DecodeUInt32_MatchesOriginalVlq()
    {
        // Test with values from the original PoC Vlq implementation
        byte[] encoded128 = [0x81, 0x00]; // 128
        var value = Vlq.DecodeUInt32(encoded128, out var len);
        Assert.That(value, Is.EqualTo(128U));
        Assert.That(len, Is.EqualTo(2));
    }
    
    [Test]
    public void DecodeUInt64_MatchesOriginalVlq()
    {
        // Test with values from the original PoC Vlq implementation
        byte[] encoded180 = [0x81, 0x34]; // 180
        var value = Vlq.DecodeUInt64(encoded180, out var len);
        Assert.That(value, Is.EqualTo(180UL));
        Assert.That(len, Is.EqualTo(2));
    }
}
