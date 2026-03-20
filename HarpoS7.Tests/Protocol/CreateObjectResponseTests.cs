using System.Text;
using HarpoS7.PoC.Packets;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.Tests.Protocol;

[TestFixture]
public class CreateObjectResponseTests
{
    [Test]
    public void FindFingerprint_WithPlcSimFingerprint_FindsCorrectly()
    {
        // Simulate a response buffer containing a fingerprint string
        // Structure: ... [0x15 (WString)] [VLQ length] [fingerprint string] ...
        var fingerprint = "03:AABBCCDDEEFF0011";
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);

        var data = new byte[100];
        var offset = 30; // put it at some offset to simulate real data
        data[offset] = S7CommPlusConstants.DataTypeWString; // 0x15
        data[offset + 1] = (byte)fingerprintBytes.Length; // VLQ length (single byte for < 128)
        fingerprintBytes.CopyTo(data.AsSpan(offset + 2));

        var result = CreateObjectResponse.FindFingerprint(data);
        Assert.That(result, Is.EqualTo(fingerprint));
    }

    [Test]
    public void FindFingerprint_WithS71500Fingerprint_FindsCorrectly()
    {
        var fingerprint = "00:1234567890ABCDEF";
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);

        var data = new byte[100];
        var offset = 20;
        data[offset] = S7CommPlusConstants.DataTypeWString;
        data[offset + 1] = (byte)fingerprintBytes.Length;
        fingerprintBytes.CopyTo(data.AsSpan(offset + 2));

        var result = CreateObjectResponse.FindFingerprint(data);
        Assert.That(result, Is.EqualTo(fingerprint));
    }

    [Test]
    public void FindFingerprint_WithS71200Fingerprint_FindsCorrectly()
    {
        var fingerprint = "01:ABCDEF0123456789";
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);

        var data = new byte[100];
        var offset = 25;
        data[offset] = S7CommPlusConstants.DataTypeWString;
        data[offset + 1] = (byte)fingerprintBytes.Length;
        fingerprintBytes.CopyTo(data.AsSpan(offset + 2));

        var result = CreateObjectResponse.FindFingerprint(data);
        Assert.That(result, Is.EqualTo(fingerprint));
    }

    [Test]
    public void FindFingerprint_WithUnknownFamily_FindsCorrectly()
    {
        // This tests the fix for issue #18 - a fingerprint with an unknown family prefix
        var fingerprint = "07:AABBCCDDEEFF0011";
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);

        var data = new byte[100];
        var offset = 15;
        data[offset] = S7CommPlusConstants.DataTypeWString;
        data[offset + 1] = (byte)fingerprintBytes.Length;
        fingerprintBytes.CopyTo(data.AsSpan(offset + 2));

        var result = CreateObjectResponse.FindFingerprint(data);
        Assert.That(result, Is.EqualTo(fingerprint));
    }

    [Test]
    public void FindFingerprint_NoFingerprint_ReturnsNull()
    {
        // Buffer with no fingerprint
        var data = new byte[50];
        data[10] = S7CommPlusConstants.DataTypeWString;
        data[11] = 5;
        Encoding.UTF8.GetBytes("Hello").CopyTo(data.AsSpan(12));

        var result = CreateObjectResponse.FindFingerprint(data);
        Assert.That(result, Is.Null);
    }

    [Test]
    public void FindFingerprint_AtDifferentOffset_StillFinds()
    {
        // Test that it works regardless of where in the buffer the fingerprint appears
        var fingerprint = "03:AABBCCDD";
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);

        // Try at different offsets
        foreach (var offset in new[] { 5, 10, 50, 80 })
        {
            var data = new byte[120];
            data[offset] = S7CommPlusConstants.DataTypeWString;
            data[offset + 1] = (byte)fingerprintBytes.Length;
            fingerprintBytes.CopyTo(data.AsSpan(offset + 2));

            var result = CreateObjectResponse.FindFingerprint(data);
            Assert.That(result, Is.EqualTo(fingerprint), $"Failed to find fingerprint at offset {offset}");
        }
    }

    [Test]
    public void FindChallenge_After_Fingerprint_FindsCorrectly()
    {
        var fingerprint = "03:AABBCCDD";
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);
        var challenge = new byte[20];
        for (int i = 0; i < 20; i++) challenge[i] = (byte)(i + 0x10);

        var data = new byte[200];
        // Place fingerprint
        var offset = 30;
        fingerprintBytes.CopyTo(data.AsSpan(offset));
        offset += fingerprintBytes.Length;

        // Some gap
        offset += 5;

        // Place challenge as OctetString: [0x05] [VLQ length=20] [20 bytes]
        data[offset] = S7CommPlusConstants.DataTypeOctetString;
        data[offset + 1] = 20; // VLQ length
        challenge.CopyTo(data.AsSpan(offset + 2));

        var result = CreateObjectResponse.FindChallenge(data, fingerprint);
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.EqualTo(challenge));
    }

    [Test]
    public void FindChallenge_AsBlobType_FindsCorrectly()
    {
        var fingerprint = "00:AABBCCDD";
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);
        var challenge = new byte[20];
        for (int i = 0; i < 20; i++) challenge[i] = (byte)(0xAA + i);

        var data = new byte[200];
        var offset = 20;
        fingerprintBytes.CopyTo(data.AsSpan(offset));
        offset += fingerprintBytes.Length + 3;

        // Place challenge as Blob: [0x14] [VLQ length=20] [20 bytes]
        data[offset] = S7CommPlusConstants.DataTypeBlob;
        data[offset + 1] = 20;
        challenge.CopyTo(data.AsSpan(offset + 2));

        var result = CreateObjectResponse.FindChallenge(data, fingerprint);
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.EqualTo(challenge));
    }

    [Test]
    public void IsValidFingerprint_ValidFormats_ReturnsTrue()
    {
        Assert.That(CreateObjectResponse.IsValidFingerprint("03:AABB"), Is.True);
        Assert.That(CreateObjectResponse.IsValidFingerprint("00:1234567890ABCDEF"), Is.True);
        Assert.That(CreateObjectResponse.IsValidFingerprint("01:aabbccdd"), Is.True);
        Assert.That(CreateObjectResponse.IsValidFingerprint("FF:0123456789ABCDEF"), Is.True);
    }

    [Test]
    public void IsValidFingerprint_InvalidFormats_ReturnsFalse()
    {
        Assert.That(CreateObjectResponse.IsValidFingerprint(""), Is.False);
        Assert.That(CreateObjectResponse.IsValidFingerprint("03:"), Is.False);
        Assert.That(CreateObjectResponse.IsValidFingerprint("03:A"), Is.False); // odd number of hex chars
        Assert.That(CreateObjectResponse.IsValidFingerprint("Hello World"), Is.False);
        Assert.That(CreateObjectResponse.IsValidFingerprint("GG:AABB"), Is.False); // invalid hex prefix
        Assert.That(CreateObjectResponse.IsValidFingerprint("03:GGGG"), Is.False); // invalid hex chars
    }
}
