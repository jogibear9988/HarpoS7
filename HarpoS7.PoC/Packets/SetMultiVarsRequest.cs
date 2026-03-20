using System.Buffers.Binary;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.PoC.Packets;

/// <summary>
/// Builds a SetMultiVariables request for S7 Comm Plus authentication.
/// This packet sends the encrypted key blob, public key ID, and symmetric key ID
/// to the PLC to complete the challenge-response authentication.
/// <para>
/// Packet structure (after TPKT/COTP):
/// <list type="bullet">
///   <item>S7CommPlus Header: [0x72] [PDU=0x02] [DataLength:2]</item>
///   <item>Opcode: [0x31 Request] [Reserved:2] [Function=0x0542] [Reserved:2] [Sequence=0x0002]</item>
///   <item>Session qualifiers: [SessionID:4] [Separator 0x34] [SessionID:4]</item>
///   <item>Item descriptors: Attribute tags describing the key exchange structure</item>
///   <item>Authentication data: Public key ID (VLQ) + Symmetric key ID (VLQ) + Encrypted blob</item>
///   <item>Footer attributes: Status and configuration attributes</item>
///   <item>S7CommPlus Trailer: [0x72] [PDU=0x02] [0x00 0x00]</item>
/// </list>
/// </para>
/// </summary>
public class SetMultiVarsRequest
{
    private readonly uint _sessionId;
    private readonly byte[] _publicKeyIdVlq;
    private readonly byte[] _symmetricKeyIdVlq;
    private readonly byte[] _blobData;

    // --- S71500 Dissected Sections ---
    // The SetMultiVars packet is split into clearly labeled sections.
    // Dynamic data (session ID, key IDs, encrypted blob) is injected between sections.

    /// <summary>
    /// S71500: Opcode + session qualifiers + item descriptors, up to the public key ID position.
    /// </summary>
    private static readonly byte[] S71500_Prefix =
    [
        // Opcode header
        0x31,                         // Opcode: Request
        0x00, 0x00,                   // Reserved
        0x05, 0x42,                   // Function: SetMultiVariables (0x0542)
        0x00, 0x00,                   // Reserved
        0x00, 0x02,                   // Sequence number: 2
        // Session qualifiers (will be patched with actual session ID)
        0x70, 0x00, 0x10, 0x3D,      // Session ID 1 (placeholder)
        0x34,                         // Separator
        0x70, 0x00, 0x10, 0x3D,      // Session ID 2 (placeholder)
        // Item count and structure descriptors
        0x02, 0x02,                   // 2 items, 2 sub-items
        0x8E, 0x26, 0x82, 0x32, 0x01, 0x00,  // Item descriptor tags
        0x17, 0x00, 0x00, 0x07, 0x08,
        0x8E, 0x09, 0x00, 0x04, 0x00,
        0x8E, 0x0A, 0x00, 0x02, 0x00,
        0x8E, 0x0B, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21,
        0x8E, 0x22, 0x00, 0x05                // Data type 0x05 = OctetString (for public key ID VLQ)
    ];

    /// <summary>
    /// S71500: Between public key ID and symmetric key ID.
    /// Contains key flags and next item descriptor.
    /// </summary>
    private static readonly byte[] S71500_BetweenKeys =
    [
        0x8E, 0x23, 0x00, 0x04, 0x10,               // Public key flags (0x10)
        0x8E, 0x24, 0x00, 0x04, 0x00, 0x00,          // Internal key flags
        0x8E, 0x0C, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21,  // Next item descriptor
        0x8E, 0x22, 0x00, 0x05                        // Data type 0x05 (for symmetric key ID VLQ)
    ];

    /// <summary>
    /// S71500: Between symmetric key ID and encrypted blob.
    /// Contains symmetric key flags and blob data type header.
    /// </summary>
    private static readonly byte[] S71500_BetweenKeyAndBlob =
    [
        0x8E, 0x23, 0x00, 0x04, 0x84, 0x80, 0x01,    // Symmetric key flags (VLQ: 0x4001)
        0x8E, 0x24, 0x00, 0x04, 0x00, 0x00,           // Internal key flags
        0x8E, 0x0D, 0x00, 0x14, 0x00                   // Blob data type (0x14) + flags
    ];

    /// <summary>
    /// S71500: Footer with status and configuration attributes.
    /// </summary>
    private static readonly byte[] S71500_Footer =
    [
        0x00, 0x02, 0x00,
        0x17, 0x00, 0x00, 0x01,
        0x3A, 0x82, 0x3B, 0x00, 0x04, 0x84, 0x00,
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

    // --- S71200 Dissected Sections ---

    private static readonly byte[] S71200_Prefix =
    [
        0x31, 0x00, 0x00, 0x05, 0x42, 0x00, 0x00, 0x00, 0x02,
        0x70, 0x40, 0x00, 0x00,  // Session ID 1 (placeholder)
        0x34,                    // Separator
        0x70, 0x40, 0x00, 0x00,  // Session ID 2 (placeholder)
        0x02, 0x02,
        0x8E, 0x26, 0x82, 0x32, 0x01, 0x00,
        0x17, 0x00, 0x00, 0x07, 0x08,
        0x8E, 0x09, 0x00, 0x04, 0x00,
        0x8E, 0x0A, 0x00, 0x02, 0x00,
        0x8E, 0x0B, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21,
        0x8E, 0x22, 0x00, 0x05
    ];

    private static readonly byte[] S71200_BetweenKeys =
    [
        0x8E, 0x23, 0x00, 0x04, 0x82, 0x10,
        0x8E, 0x24, 0x00, 0x04, 0x00, 0x00,
        0x8E, 0x0C, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21,
        0x8E, 0x22, 0x00, 0x05
    ];

    private static readonly byte[] S71200_BetweenKeyAndBlob =
    [
        0x8E, 0x23, 0x00, 0x04, 0x84, 0x82, 0x01,
        0x8E, 0x24, 0x00, 0x04, 0x00, 0x00,
        0x8E, 0x0D, 0x00, 0x14, 0x00
    ];

    private static readonly byte[] S71200_Footer =
    [
        0x00, 0x02, 0x00,
        0x17, 0x00, 0x00, 0x01,
        0x3A, 0x82, 0x3B, 0x00, 0x04, 0x84, 0x00,
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

    // --- PlcSim Dissected Sections ---

    private static readonly byte[] PlcSim_Prefix =
    [
        0x31, 0x00, 0x00, 0x05, 0x42, 0x00, 0x00, 0x00, 0x02,
        0x70, 0x40, 0x00, 0x00,  // Session ID 1 (placeholder)
        0x34,                    // Separator
        0x70, 0x40, 0x00, 0x00,  // Session ID 2 (placeholder)
        0x03, 0x03,              // 3 items, 3 sub-items
        0x8E, 0x26, 0x82, 0x32, 0x82, 0x2B,
        0x01, 0x00,
        0x17, 0x00, 0x00, 0x07, 0x08,
        0x8E, 0x09, 0x00, 0x04, 0x00,
        0x8E, 0x0A, 0x00, 0x02, 0x00,
        0x8E, 0x0B, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21,
        0x8E, 0x22, 0x00, 0x05
    ];

    private static readonly byte[] PlcSim_BetweenKeys =
    [
        0x8E, 0x23, 0x00, 0x04, 0x86, 0x10,
        0x8E, 0x24, 0x00, 0x04, 0x00, 0x00,
        0x8E, 0x0C, 0x00, 0x17, 0x00, 0x00, 0x07, 0x21,
        0x8E, 0x22, 0x00, 0x05
    ];

    private static readonly byte[] PlcSim_BetweenKeyAndBlob =
    [
        0x8E, 0x23, 0x00, 0x04, 0x84, 0x86, 0x01,
        0x8E, 0x24, 0x00, 0x04, 0x00, 0x00,
        0x8E, 0x0D, 0x00, 0x14, 0x00
    ];

    private static readonly byte[] PlcSim_Footer =
    [
        0x00, 0x02, 0x00,
        0x17, 0x00, 0x00, 0x01,
        0x3A, 0x82, 0x3B, 0x00, 0x04, 0x85, 0x40,
        0x82, 0x3C, 0x00, 0x04, 0x85, 0x00,
        0x82, 0x3D, 0x00, 0x04, 0x84, 0x80, 0xC1, 0x00,
        0x82, 0x3E, 0x00, 0x04, 0x84, 0x80, 0xC1, 0x00,
        0x82, 0x3F, 0x00, 0x15, 0x00,
        0x82, 0x40, 0x00, 0x15, 0x00,
        0x82, 0x41, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];

    // Session ID offsets within the prefix sections (relative to prefix start)
    private const int SessionIdOffset1 = 9;   // First session ID in prefix
    private const int SessionIdOffset2 = 14;  // Second session ID (after 0x34 separator)

    public SetMultiVarsRequest(
        ReadOnlySpan<byte> publicKeyId,
        ReadOnlySpan<byte> symmetricKeyId,
        ReadOnlySpan<byte> blobData,
        uint sessionId)
    {
        _sessionId = sessionId;

        var pubKeyIdUlong = BinaryPrimitives.ReadUInt64LittleEndian(publicKeyId);
        var symmetricKeyIdUlong = BinaryPrimitives.ReadUInt64LittleEndian(symmetricKeyId);

        Span<byte> publicKeyIdVlq = stackalloc byte[9];
        Span<byte> symKeyIdVlq = stackalloc byte[9];
        var pubLength = pubKeyIdUlong.EncodeAsVlq(publicKeyIdVlq);
        var symLength = symmetricKeyIdUlong.EncodeAsVlq(symKeyIdVlq);

        _publicKeyIdVlq = publicKeyIdVlq[..pubLength].ToArray();
        _symmetricKeyIdVlq = symKeyIdVlq[..symLength].ToArray();
        _blobData = blobData.ToArray();
    }

    /// <summary>
    /// Write S71500 SetMultiVars request. Assembles the packet from dissected sections
    /// and injects session ID, key IDs, and encrypted blob data.
    /// </summary>
    public void WriteS71500(Stream stream)
    {
        WritePacket(stream, S71500_Prefix, S71500_BetweenKeys, S71500_BetweenKeyAndBlob, S71500_Footer);
    }

    /// <summary>
    /// Write S71200 SetMultiVars request.
    /// </summary>
    public void WriteS71200(Stream stream)
    {
        WritePacket(stream, S71200_Prefix, S71200_BetweenKeys, S71200_BetweenKeyAndBlob, S71200_Footer);
    }

    /// <summary>
    /// Write PLC-SIM SetMultiVars request.
    /// </summary>
    public void WritePlcSim(Stream stream)
    {
        WritePacket(stream, PlcSim_Prefix, PlcSim_BetweenKeys, PlcSim_BetweenKeyAndBlob, PlcSim_Footer);
    }

    /// <summary>
    /// Assemble and write the packet from its dissected sections.
    /// The packet is built by concatenating: [TPKT+COTP] [S7CommPlus Header] [Prefix]
    /// [PubKeyID] [BetweenKeys] [SymKeyID] [BetweenKeyAndBlob] [Blob] [Footer] [Trailer]
    /// </summary>
    private void WritePacket(Stream stream, byte[] prefix, byte[] betweenKeys, byte[] betweenKeyAndBlob, byte[] footer)
    {
        // Calculate S7CommPlus data area size (between header and trailer)
        var dataSize = prefix.Length
            + _publicKeyIdVlq.Length
            + betweenKeys.Length
            + _symmetricKeyIdVlq.Length
            + betweenKeyAndBlob.Length
            + _blobData.Length
            + footer.Length;

        // Total packet size including TPKT(4) + COTP(3) + header(4) + data + trailer(4)
        var totalSize = 4 + 3 + S7CommPlusConstants.HeaderLength + dataSize + S7CommPlusConstants.TrailerLength;
        Span<byte> packet = stackalloc byte[totalSize];

        var offset = 0;

        // TPKT header
        packet[offset++] = 0x03; // version
        packet[offset++] = 0x00; // reserved
        BinaryPrimitives.WriteUInt16BigEndian(packet[offset..], (ushort)totalSize);
        offset += 2;

        // COTP DT Data header
        packet[offset++] = 0x02; // length
        packet[offset++] = 0xF0; // DT Data PDU type
        packet[offset++] = 0x80; // last data unit

        // S7CommPlus header
        var header = new S7CommPlusHeader
        {
            PduType = S7CommPlusConstants.PduTypeData,
            DataLength = (ushort)dataSize
        };
        header.WriteTo(packet[offset..]);
        offset += S7CommPlusConstants.HeaderLength;

        // Prefix section (opcode + session qualifiers + item descriptors)
        prefix.CopyTo(packet[offset..]);
        // Patch session IDs in the prefix
        BinaryPrimitives.WriteUInt32BigEndian(packet[(offset + SessionIdOffset1)..], _sessionId);
        BinaryPrimitives.WriteUInt32BigEndian(packet[(offset + SessionIdOffset2)..], _sessionId);
        offset += prefix.Length;

        // Public key ID (VLQ encoded)
        _publicKeyIdVlq.CopyTo(packet[offset..]);
        offset += _publicKeyIdVlq.Length;

        // Between keys section (key flags + next item descriptor)
        betweenKeys.CopyTo(packet[offset..]);
        offset += betweenKeys.Length;

        // Symmetric key ID (VLQ encoded)
        _symmetricKeyIdVlq.CopyTo(packet[offset..]);
        offset += _symmetricKeyIdVlq.Length;

        // Between key and blob section (key flags + blob data type header)
        betweenKeyAndBlob.CopyTo(packet[offset..]);
        offset += betweenKeyAndBlob.Length;

        // Encrypted blob data
        _blobData.CopyTo(packet[offset..]);
        offset += _blobData.Length;

        // Footer section (status and configuration attributes)
        footer.CopyTo(packet[offset..]);
        offset += footer.Length;

        // S7CommPlus trailer
        header.WriteTrailerTo(packet[offset..]);

        stream.Write(packet);
    }
}