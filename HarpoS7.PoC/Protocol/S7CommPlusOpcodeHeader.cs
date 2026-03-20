using System.Buffers.Binary;

namespace HarpoS7.PoC.Protocol;

/// <summary>
/// Represents the opcode area that follows the S7CommPlus frame header
/// (or follows integrity data for PDU type 3).
/// <para>
/// Structure: [Opcode:1] [Reserved:2] [Function:2] [Reserved:2] [SequenceNumber:2]
/// </para>
/// </summary>
public struct S7CommPlusOpcodeHeader
{
    /// <summary>Opcode: 0x31 Request, 0x32 Response, 0x33 Notification</summary>
    public byte Opcode { get; set; }

    /// <summary>Function code (e.g. 0x04CA=CreateObject, 0x0542=SetMultiVariables)</summary>
    public ushort Function { get; set; }

    /// <summary>Packet sequence number</summary>
    public ushort SequenceNumber { get; set; }

    /// <summary>Total serialized length in bytes</summary>
    public const int SerializedLength = 9; // opcode(1) + reserved(2) + function(2) + reserved(2) + sequence(2)

    /// <summary>Parse the opcode header from the given span</summary>
    public static S7CommPlusOpcodeHeader Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < SerializedLength)
            throw new ArgumentException("Data too short for opcode header");

        return new S7CommPlusOpcodeHeader
        {
            Opcode = data[0],
            Function = BinaryPrimitives.ReadUInt16BigEndian(data[3..]),
            SequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(data[7..])
        };
    }

    /// <summary>Write the 9-byte opcode header to the destination</summary>
    public readonly void WriteTo(Span<byte> destination)
    {
        destination[0] = Opcode;
        destination[1] = 0x00; // reserved
        destination[2] = 0x00;
        BinaryPrimitives.WriteUInt16BigEndian(destination[3..], Function);
        destination[5] = 0x00; // reserved
        destination[6] = 0x00;
        BinaryPrimitives.WriteUInt16BigEndian(destination[7..], SequenceNumber);
    }
}
