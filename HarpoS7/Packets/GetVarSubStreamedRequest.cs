using System.Buffers.Binary;
using HarpoS7.Integrity;

namespace HarpoS7.Packets;

/// <summary>
/// Builds a GetVarSubStreamed request packet for requesting a legitimation challenge.
/// This packet includes an HMAC-SHA256 integrity digest computed over the data section.
/// </summary>
public static class GetVarSubStreamedRequest
{
    private const byte Opcode = 0x03;
    private const byte MarkerByte = 0x20;
    private const byte SessionIdSeparator = 0x34;

    // Function header for GetVarSubStreamed (different reserved bytes from SetMultiVars)
    private static readonly byte[] FunctionHeader =
    [
        0x31,                         // Function/sequence ID
        0x00, 0x00, 0x05, 0x86,       // Reserved
        0x00, 0x00, 0x00, 0x03        // Unknown
    ];

    // Static footer after session IDs
    private static readonly byte[] PostSessionFooter =
    [
        0x20, 0x04, 0x01,
        0x82, 0x2F,                   // Tag 0x822F
        0x00,
        0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00
    ];

    /// <summary>
    /// Serializes a GetVarSubStreamed request packet for real PLCs (S7-1200/S7-1500).
    /// The returned byte array is the S7CommPlus payload (without TPKT/COTP framing).
    /// </summary>
    /// <param name="sessionKey">The 24-byte session key from authentication</param>
    /// <param name="sessionId">The session ID from the CreateObject response</param>
    /// <returns>The serialized S7CommPlus packet bytes</returns>
    public static byte[] Serialize(ReadOnlySpan<byte> sessionKey, uint sessionId)
    {
        // Build the data section that will be integrity-checked
        // Structure: [function_header(9)] [session_id(4)] [separator(1)] [session_id(4)] [footer(35)]
        var dataToHash = BuildDataSection(sessionId);

        // Build the complete S7+ data: [marker(1)] [digest(32)] [data_section(53)]
        using var writer = new S7CommPlusPacketWriter(Opcode);

        // Marker byte
        writer.WriteByte(MarkerByte);

        // Calculate and write the integrity digest
        Span<byte> digest = stackalloc byte[HarpoPacketDigest.DigestLength];
        HarpoPacketDigest.CalculateDigest(digest, dataToHash, sessionKey);
        writer.Write(digest);

        // Write the data section
        writer.Write(dataToHash);

        return writer.ToPacket();
    }

    private static byte[] BuildDataSection(uint sessionId)
    {
        var dataLength = FunctionHeader.Length + 4 + 1 + 4 + PostSessionFooter.Length;
        var data = new byte[dataLength];
        var offset = 0;

        // Function header
        FunctionHeader.CopyTo(data.AsSpan(offset));
        offset += FunctionHeader.Length;

        // Session ID 1
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset), sessionId);
        offset += 4;

        // Separator
        data[offset++] = SessionIdSeparator;

        // Session ID 2
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset), sessionId);
        offset += 4;

        // Post-session footer
        PostSessionFooter.CopyTo(data.AsSpan(offset));

        return data;
    }
}
