using System.Buffers.Binary;

namespace HarpoS7.PoC.Protocol;

/// <summary>
/// Represents the S7 Comm Plus frame header and provides trailer serialization.
/// <para>
/// Frame structure: [0x72] [PDUType:1] [DataLength:2] [Data...] [0x72] [PDUType:1] [0x00 0x00]
/// </para>
/// </summary>
public struct S7CommPlusHeader
{
    /// <summary>PDU type: 0x01 Connect, 0x02 Data, 0x03 Data with integrity</summary>
    public byte PduType { get; set; }

    /// <summary>Length of the data area between header and trailer</summary>
    public ushort DataLength { get; set; }

    /// <summary>Parse a header from S7CommPlus data at the start of the span</summary>
    public static S7CommPlusHeader Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < S7CommPlusConstants.HeaderLength)
            throw new ArgumentException("Data too short for S7CommPlus header");

        if (data[0] != S7CommPlusConstants.ProtocolId)
            throw new InvalidDataException(
                $"Invalid protocol ID: 0x{data[0]:X2}, expected 0x{S7CommPlusConstants.ProtocolId:X2}");

        return new S7CommPlusHeader
        {
            PduType = data[1],
            DataLength = BinaryPrimitives.ReadUInt16BigEndian(data[2..])
        };
    }

    /// <summary>Write the 4-byte header to the destination</summary>
    public readonly void WriteTo(Span<byte> destination)
    {
        destination[0] = S7CommPlusConstants.ProtocolId;
        destination[1] = PduType;
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], DataLength);
    }

    /// <summary>Write the 4-byte trailer to the destination</summary>
    public readonly void WriteTrailerTo(Span<byte> destination)
    {
        destination[0] = S7CommPlusConstants.ProtocolId;
        destination[1] = PduType;
        destination[2] = 0x00;
        destination[3] = 0x00;
    }
}
