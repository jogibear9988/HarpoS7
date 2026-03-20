using System.Buffers.Binary;
using HarpoS7.Utilities.Auth;

namespace HarpoS7.Packets;

/// <summary>
/// Builds a SetMultiVars request packet for authenticating an S7CommPlus session.
/// This packet carries the encrypted authentication blob, public key ID, and symmetric key ID.
/// </summary>
public static class SetMultiVarsRequest
{
    private const byte Opcode = 0x02;

    // S7CommPlus function header (common to all device families)
    private static readonly byte[] FunctionHeader =
    [
        0x31,                         // Function/sequence ID
        0x00, 0x00, 0x05, 0x42,       // Reserved
        0x00, 0x00, 0x00, 0x02        // Unknown
    ];

    private const byte SessionIdSeparator = 0x34;

    // Item prefix for real PLCs (S7-1500, S7-1200)
    private static readonly byte[] RealPlcItemPrefix =
    [
        0x02, 0x02,                   // Item count / sub-item count
        0x8E, 0x26,                   // SetMultiVars outer tag
        0x82, 0x32,                   // Sub-tag
        0x01                          // Flag
    ];

    // Item prefix for PLCSim (has additional 0x82, 0x2B sub-tag)
    private static readonly byte[] PlcSimItemPrefix =
    [
        0x03, 0x03,                   // Item count / sub-item count (different for PlcSim)
        0x8E, 0x26,                   // SetMultiVars outer tag
        0x82, 0x32,                   // Sub-tag
        0x82, 0x2B,                   // Additional PlcSim sub-tag
        0x01                          // Flag
    ];

    // Item structure header (common to all families)
    // Contains the struct type (0x17) and struct ID (0x000708),
    // followed by two initialization tags (0x8E09 and 0x8E0A)
    private static readonly byte[] ItemStructHeader =
    [
        0x00, 0x17,                   // Flags + Struct type
        0x00, 0x00, 0x07, 0x08,       // Struct ID
        0x8E, 0x09, 0x00, 0x04, 0x00, // Tag 0x8E09: UDInt = 0
        0x8E, 0x0A, 0x00, 0x02, 0x00  // Tag 0x8E0A: UInt = 0
    ];

    // Key struct header bytes: struct tag prefix (type 0x17, struct ID 0x000721)
    private static readonly byte[] KeyStructHeader = [0x00, 0x17, 0x00, 0x00, 0x07, 0x21];

    // Tag constants for key structures
    private static readonly byte[] PubKeyStructTag = [0x8E, 0x0B];
    private static readonly byte[] SymKeyStructTag = [0x8E, 0x0C];
    private static readonly byte[] KeyIdTagPrefix = [0x8E, 0x22, 0x00, 0x05];   // UInt64 type
    private static readonly byte[] KeyFlagsTagPrefix = [0x8E, 0x23, 0x00, 0x04]; // UDInt type
    private static readonly byte[] Tag24Value = [0x8E, 0x24, 0x00, 0x04, 0x00];  // UDInt = 0
    private const byte EndOfStruct = 0x00;

    // Blob tag prefix (tag 0x8E0D, Blob type 0x14)
    private static readonly byte[] BlobTagPrefix = [0x8E, 0x0D, 0x00, 0x14, 0x00];

    // Per-family footer bytes (static protocol fields after the blob data)
    private static readonly byte[] S71500Footer =
    [
        0x00, 0x02, 0x00, 0x17, 0x00, 0x00, 0x01, 0x3A,
        0x82, 0x3B, 0x00, 0x04, 0x84, 0x00,
        0x82, 0x3C, 0x00, 0x04, 0x84, 0x00,
        0x82, 0x3D, 0x00, 0x04, 0x84, 0x81, 0x82, 0x40,
        0x82, 0x3E, 0x00, 0x04, 0x84, 0x81, 0x82, 0x40,
        0x82, 0x3F, 0x00, 0x15, 0x00,
        0x82, 0x40, 0x00, 0x15, 0x00,
        0x82, 0x41, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];

    private static readonly byte[] S71200Footer =
    [
        0x00, 0x02, 0x00, 0x17, 0x00, 0x00, 0x01, 0x3A,
        0x82, 0x3B, 0x00, 0x04, 0x84, 0x00,
        0x82, 0x3C, 0x00, 0x04, 0x84, 0x00,
        0x82, 0x3D, 0x00, 0x04, 0x84, 0x80, 0xC2, 0x40,
        0x82, 0x3E, 0x00, 0x04, 0x84, 0x80, 0xC2, 0x40,
        0x82, 0x3F, 0x00, 0x15, 0x00,
        0x82, 0x40, 0x00, 0x15, 0x05, 0x32, 0x3B, 0x38, 0x33, 0x34,
        0x82, 0x41, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];

    private static readonly byte[] PlcSimFooter =
    [
        0x00, 0x02, 0x00, 0x17, 0x00, 0x00, 0x01, 0x3A,
        0x82, 0x3B, 0x00, 0x04, 0x85, 0x40,
        0x82, 0x3C, 0x00, 0x04, 0x85, 0x00,
        0x82, 0x3D, 0x00, 0x04, 0x84, 0x80, 0xC1, 0x00,
        0x82, 0x3E, 0x00, 0x04, 0x84, 0x80, 0xC1, 0x00,
        0x82, 0x3F, 0x00, 0x15, 0x00,
        0x82, 0x40, 0x00, 0x15, 0x00,
        0x82, 0x41, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00,
        0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];

    /// <summary>
    /// Serializes a SetMultiVars request packet for the specified device family.
    /// The returned byte array is the S7CommPlus payload (without TPKT/COTP framing).
    /// </summary>
    /// <param name="sessionId">The session ID from the CreateObject response</param>
    /// <param name="publicKeyId">The 8-byte public key ID (little-endian)</param>
    /// <param name="symmetricKeyId">The 8-byte symmetric key ID (little-endian)</param>
    /// <param name="blobData">The encrypted authentication blob</param>
    /// <param name="keyFamily">The PLC device family</param>
    /// <returns>The serialized S7CommPlus packet bytes</returns>
    public static byte[] Serialize(
        uint sessionId,
        ReadOnlySpan<byte> publicKeyId,
        ReadOnlySpan<byte> symmetricKeyId,
        ReadOnlySpan<byte> blobData,
        EPublicKeyFamily keyFamily)
    {
        using var writer = new S7CommPlusPacketWriter(Opcode);

        // Function header (common)
        writer.Write(FunctionHeader);

        // Session ID block (two copies separated by 0x34)
        writer.WriteUInt32BigEndian(sessionId);
        writer.WriteByte(SessionIdSeparator);
        writer.WriteUInt32BigEndian(sessionId);

        // Item prefix (family-specific)
        writer.Write(keyFamily == EPublicKeyFamily.PlcSim ? PlcSimItemPrefix : RealPlcItemPrefix);

        // Item struct header (common)
        writer.Write(ItemStructHeader);

        // Public key struct
        var publicKeyFlags = (uint)BlobMetadataWriter.GetPublicKeyFlags(keyFamily);
        WriteKeyStruct(writer, PubKeyStructTag, publicKeyId, publicKeyFlags);

        // Symmetric key struct
        var symmetricKeyFlags = (uint)BlobMetadataWriter.GetSymmetricKeyFlags(keyFamily) + 0x10000;
        WriteKeyStruct(writer, SymKeyStructTag, symmetricKeyId, symmetricKeyFlags);

        // Blob data
        writer.Write(BlobTagPrefix);
        writer.WriteVlqUInt32((uint)blobData.Length);
        writer.Write(blobData);

        // Footer (family-specific)
        writer.Write(GetFooter(keyFamily));

        return writer.ToPacket();
    }

    private static void WriteKeyStruct(
        S7CommPlusPacketWriter writer,
        ReadOnlySpan<byte> structTag,
        ReadOnlySpan<byte> keyId,
        uint flags)
    {
        // Struct tag and header
        writer.Write(structTag);
        writer.Write(KeyStructHeader);

        // Key ID (VLQ-encoded 64-bit value)
        writer.Write(KeyIdTagPrefix);
        var keyIdUlong = BinaryPrimitives.ReadUInt64LittleEndian(keyId);
        writer.WriteVlqUInt64(keyIdUlong);

        // Flags (VLQ-encoded 32-bit value)
        writer.Write(KeyFlagsTagPrefix);
        writer.WriteVlqUInt32(flags);

        // Tag 0x24 (always 0)
        writer.Write(Tag24Value);

        // End of struct marker
        writer.WriteByte(EndOfStruct);
    }

    private static ReadOnlySpan<byte> GetFooter(EPublicKeyFamily keyFamily) => keyFamily switch
    {
        EPublicKeyFamily.S71500 => S71500Footer,
        EPublicKeyFamily.S71200 => S71200Footer,
        EPublicKeyFamily.PlcSim => PlcSimFooter,
        _ => throw new ArgumentException("Unsupported key family", nameof(keyFamily))
    };
}
