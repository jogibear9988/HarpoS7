using System.Buffers.Binary;
using HarpoS7.Integrity;

namespace HarpoS7.Packets;

/// <summary>
/// Builds a SetVarSubStreamed request packet for sending a legitimation challenge response.
/// This packet carries the encrypted legitimation blob and includes an HMAC-SHA256 integrity digest.
/// </summary>
public static class SetVarSubStreamedRequest
{
    private const byte Opcode = 0x03;
    private const byte MarkerByte = 0x20;
    private const byte SessionIdSeparator = 0x34;

    // Function header for SetVarSubStreamed
    private static readonly byte[] FunctionHeader =
    [
        0x31,                         // Function/sequence ID
        0x00, 0x00, 0x05, 0x7C,       // Reserved
        0x00, 0x00, 0x00, 0x04        // Unknown
    ];

    // Pre-blob tags (between session IDs and blob data)
    private static readonly byte[] PreBlobTags =
    [
        0x20, 0x04, 0x01,
        0x8E, 0x36,                   // Tag 0x8E36
        0x00,
        0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x14, 0x00, 0x81, 0x78  // Blob tag prefix with VLQ length 248
    ];

    // Post-blob tags (after blob data, before S7+ trailer)
    private static readonly byte[] PostBlobTags =
    [
        0x03, 0x00, 0x00, 0x00, 0x00
    ];

    /// <summary>
    /// Serializes a SetVarSubStreamed request packet for real PLCs (S7-1200/S7-1500).
    /// The returned byte array is the S7CommPlus payload (without TPKT/COTP framing).
    /// </summary>
    /// <param name="sessionKey">The 24-byte session key from authentication</param>
    /// <param name="blobData">The encrypted legitimation blob (248 bytes for real PLC)</param>
    /// <param name="sessionId">The session ID from the CreateObject response</param>
    /// <returns>The serialized S7CommPlus packet bytes</returns>
    public static byte[] Serialize(
        ReadOnlySpan<byte> sessionKey,
        ReadOnlySpan<byte> blobData,
        uint sessionId)
    {
        // Build the data section that will be integrity-checked
        // Structure: [function_header(9)] [session_ids(9)] [pre_blob(35)] [blob(248)] [post_blob(5)]
        var dataToHash = BuildDataSection(sessionId, blobData);

        // Build the complete S7+ data: [marker(1)] [digest(32)] [data_section(306)]
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

    private static byte[] BuildDataSection(uint sessionId, ReadOnlySpan<byte> blobData)
    {
        var dataLength = FunctionHeader.Length + 4 + 1 + 4
                         + PreBlobTags.Length + blobData.Length + PostBlobTags.Length;
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

        // Pre-blob tags
        PreBlobTags.CopyTo(data.AsSpan(offset));
        offset += PreBlobTags.Length;

        // Blob data
        blobData.CopyTo(data.AsSpan(offset));
        offset += blobData.Length;

        // Post-blob tags
        PostBlobTags.CopyTo(data.AsSpan(offset));

        return data;
    }
}
