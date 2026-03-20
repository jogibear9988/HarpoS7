using System.Buffers.Binary;
using HarpoS7.Integrity;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.PoC.Packets;

/// <summary>
/// Builds a SetVarSubStreamed request for sending the legitimation (password) challenge response.
/// <para>
/// Packet structure (after TPKT/COTP):
/// <list type="bullet">
///   <item>S7CommPlus Header: [0x72] [PDU=0x03] [DataLength:2]</item>
///   <item>Integrity part: [0x20] [HMAC-SHA256:32]</item>
///   <item>Data part marker: [0x8B]</item>
///   <item>Opcode: [0x31 Request] [Reserved:2] [Function=0x057C] [Reserved:2] [Sequence=0x0004]</item>
///   <item>Session qualifiers: [SessionID:4] [Separator 0x34] [SessionID:4]</item>
///   <item>Write parameters: Item descriptors + legitimation blob data</item>
///   <item>S7CommPlus Trailer: [0x72] [PDU=0x03] [0x00 0x00]</item>
/// </list>
/// </para>
/// </summary>
public class SetVarSubStreamedRequest
{
    private readonly byte[] _sessionKey;
    private readonly byte[] _blob;
    private readonly uint _sessionId;

    /// <summary>
    /// Data part prefix: [DataPartId] [Opcode header] [Session qualifiers] [Write parameter header].
    /// Ends before the blob data insertion point.
    /// </summary>
    private static readonly byte[] DataPrefix =
    [
        S7CommPlusConstants.DataPartId,    // 0x8B - data part marker
        // Opcode header
        S7CommPlusConstants.OpcodeRequest, // 0x31 - Request
        0x00, 0x00,                        // Reserved
        0x05, 0x7C,                        // Function: SetVarSubStreamed (0x057C)
        0x00, 0x00,                        // Reserved
        0x00, 0x04,                        // Sequence number: 4
        // Session qualifiers (will be patched)
        0x70, 0x40, 0x00, 0x00,            // Session ID 1 (placeholder)
        0x34,                              // Separator
        0x70, 0x40, 0x00, 0x00,            // Session ID 2 (placeholder)
        // Write parameters header (item descriptors for legitimation)
        0x20, 0x04, 0x01,
        0x8E, 0x36, 0x00, 0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x14, 0x00
        // Legitimation blob data follows here
    ];

    /// <summary>
    /// Data part suffix: Termination bytes after the blob data.
    /// </summary>
    private static readonly byte[] DataSuffix =
    [
        0x03, 0x00, 0x00, 0x00, 0x00
    ];

    // Session ID offsets within the data prefix
    private const int DataSessionIdOffset1 = 10;
    private const int DataSessionIdOffset2 = 15;

    public SetVarSubStreamedRequest(byte[] sessionKey, byte[] blob, uint sessionId)
    {
        _sessionKey = sessionKey;
        _blob = blob;
        _sessionId = sessionId;
    }

    /// <summary>
    /// Write the SetVarSubStreamed request to the stream.
    /// Includes TPKT/COTP headers, S7CommPlus framing, integrity calculation, and blob data.
    /// </summary>
    public void WriteRealPlc(Stream stream)
    {
        // Calculate data part size
        var dataPartLength = DataPrefix.Length + _blob.Length + DataSuffix.Length;
        var s7DataLength = 1 + HarpoPacketDigest.DigestLength + dataPartLength; // IntegrityId(1) + HMAC(32) + data

        // Total = TPKT(4) + COTP(3) + S7CommPlus header(4) + data area + trailer(4)
        var totalSize = 4 + 3 + S7CommPlusConstants.HeaderLength + s7DataLength + S7CommPlusConstants.TrailerLength;
        Span<byte> buffer = stackalloc byte[totalSize];

        var offset = 0;

        // TPKT header
        buffer[offset++] = 0x03;
        buffer[offset++] = 0x00;
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..], (ushort)totalSize);
        offset += 2;

        // COTP DT Data
        buffer[offset++] = 0x02;
        buffer[offset++] = 0xF0;
        buffer[offset++] = 0x80;

        // S7CommPlus header
        var header = new S7CommPlusHeader
        {
            PduType = S7CommPlusConstants.PduTypeDataWithIntegrity,
            DataLength = (ushort)s7DataLength
        };
        header.WriteTo(buffer[offset..]);
        offset += S7CommPlusConstants.HeaderLength;

        // Integrity part ID
        buffer[offset++] = S7CommPlusConstants.IntegrityPartId; // 0x20

        // Reserve space for integrity HMAC (32 bytes)
        var integrityOffset = offset;
        offset += HarpoPacketDigest.DigestLength;

        // Data part prefix (with session IDs patched)
        var dataOffset = offset;
        DataPrefix.CopyTo(buffer[offset..]);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + DataSessionIdOffset1)..], _sessionId);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + DataSessionIdOffset2)..], _sessionId);
        offset += DataPrefix.Length;

        // Legitimation blob data
        _blob.CopyTo(buffer[offset..]);
        offset += _blob.Length;

        // Data suffix
        DataSuffix.CopyTo(buffer[offset..]);
        offset += DataSuffix.Length;

        // S7CommPlus trailer
        header.WriteTrailerTo(buffer[offset..]);

        // Calculate integrity (HMAC over entire data part)
        HarpoPacketDigest.CalculateDigest(
            buffer[integrityOffset..],
            buffer.Slice(dataOffset, dataPartLength),
            _sessionKey.AsSpan()
        );

        stream.Write(buffer);
    }
}