using System.Buffers.Binary;
using HarpoS7.Integrity;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.PoC.Packets;

/// <summary>
/// Builds a GetVarSubStreamed request for requesting a legitimation challenge.
/// <para>
/// Packet structure (after TPKT/COTP):
/// <list type="bullet">
///   <item>S7CommPlus Header: [0x72] [PDU=0x03] [DataLength:2]</item>
///   <item>Integrity part: [0x20] [HMAC-SHA256:32]</item>
///   <item>Data part marker: [0x8B]</item>
///   <item>Opcode: [0x31 Request] [Reserved:2] [Function=0x0586] [Reserved:2] [Sequence=0x0003]</item>
///   <item>Session qualifiers: [SessionID:4] [Separator 0x34] [SessionID:4]</item>
///   <item>Request data: Variable read parameters</item>
///   <item>S7CommPlus Trailer: [0x72] [PDU=0x03] [0x00 0x00]</item>
/// </list>
/// </para>
/// </summary>
public class GetVarSubStreamedRequest
{
    private readonly uint _sessionId;
    private readonly byte[] _sessionKey;

    /// <summary>
    /// Data part of the packet (after integrity, including 0x8B marker).
    /// Contains: [DataPartId] [Opcode header] [Session qualifiers] [Request parameters]
    /// </summary>
    private static readonly byte[] DataTemplate =
    [
        S7CommPlusConstants.DataPartId,  // 0x8B - data part marker
        // Opcode header
        S7CommPlusConstants.OpcodeRequest, // 0x31 - Request
        0x00, 0x00,                        // Reserved
        0x05, 0x86,                        // Function: GetVarSubStreamed (0x0586)
        0x00, 0x00,                        // Reserved
        0x00, 0x03,                        // Sequence number: 3
        // Session qualifiers (will be patched)
        0x70, 0x40, 0x00, 0x00,            // Session ID 1 (placeholder)
        0x34,                              // Separator
        0x70, 0x40, 0x00, 0x00,            // Session ID 2 (placeholder)
        // Request parameters (variable read request for legitimation challenge)
        0x20, 0x04, 0x01,
        0x82, 0x2F, 0x00, 0x00, 0x04, 0xE8,
        0x89, 0x69, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x6A, 0x00, 0x13, 0x00,
        0x89, 0x6B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00
    ];

    // Session ID offsets within the data template (relative to template start)
    private const int DataSessionIdOffset1 = 10; // First session ID position
    private const int DataSessionIdOffset2 = 15; // Second session ID (after separator)

    public GetVarSubStreamedRequest(ReadOnlySpan<byte> sessionKey, uint sessionId)
    {
        _sessionId = sessionId;
        _sessionKey = new byte[sessionKey.Length];
        sessionKey.CopyTo(_sessionKey.AsSpan());
    }

    /// <summary>
    /// Write the GetVarSubStreamed request to the stream.
    /// Includes TPKT/COTP headers, S7CommPlus framing, and integrity calculation.
    /// </summary>
    public void WriteRealPlc(Stream stream)
    {
        // Calculate sizes
        var dataPartLength = DataTemplate.Length;
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

        // Reserve space for integrity (HMAC-SHA256, 32 bytes) - will be calculated below
        var integrityOffset = offset;
        offset += HarpoPacketDigest.DigestLength;

        // Data part (with session IDs patched)
        DataTemplate.CopyTo(buffer[offset..]);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + DataSessionIdOffset1)..], _sessionId);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + DataSessionIdOffset2)..], _sessionId);
        var dataOffset = offset;
        offset += dataPartLength;

        // S7CommPlus trailer
        header.WriteTrailerTo(buffer[offset..]);

        // Calculate integrity (HMAC over data part)
        HarpoPacketDigest.CalculateDigest(
            buffer[integrityOffset..],
            buffer.Slice(dataOffset, dataPartLength),
            _sessionKey.AsSpan()
        );

        stream.Write(buffer);
    }
}