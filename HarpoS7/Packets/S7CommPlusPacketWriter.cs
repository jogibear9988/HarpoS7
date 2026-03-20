using System.Buffers.Binary;

namespace HarpoS7.Packets;

/// <summary>
/// Builds S7CommPlus packets by writing segments to a buffer and framing them with
/// the S7CommPlus header and trailer.
/// </summary>
internal sealed class S7CommPlusPacketWriter : IDisposable
{
    private const byte ProtocolMagic = 0x72;
    private const int HeaderLength = 4;
    private const int TrailerLength = 4;

    private readonly MemoryStream _data = new();
    private readonly byte _opcode;

    public S7CommPlusPacketWriter(byte opcode)
    {
        _opcode = opcode;
    }

    /// <summary>
    /// Gets the current number of data bytes written.
    /// </summary>
    public long DataLength => _data.Length;

    /// <summary>
    /// Writes raw bytes to the data section.
    /// </summary>
    public void Write(ReadOnlySpan<byte> bytes)
    {
        _data.Write(bytes);
    }

    /// <summary>
    /// Writes a single byte to the data section.
    /// </summary>
    public void WriteByte(byte value)
    {
        _data.WriteByte(value);
    }

    /// <summary>
    /// Writes a 32-bit unsigned integer in big-endian format.
    /// </summary>
    public void WriteUInt32BigEndian(uint value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        _data.Write(buf);
    }

    /// <summary>
    /// Writes a 16-bit unsigned integer in big-endian format.
    /// </summary>
    public void WriteUInt16BigEndian(ushort value)
    {
        Span<byte> buf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buf, value);
        _data.Write(buf);
    }

    /// <summary>
    /// Writes a VLQ-encoded 64-bit unsigned integer.
    /// </summary>
    public void WriteVlqUInt64(ulong value)
    {
        Span<byte> buf = stackalloc byte[9];
        var len = Vlq.Encode(value, buf);
        _data.Write(buf[..len]);
    }

    /// <summary>
    /// Writes a VLQ-encoded 32-bit unsigned integer.
    /// </summary>
    public void WriteVlqUInt32(uint value)
    {
        WriteVlqUInt64(value);
    }

    /// <summary>
    /// Builds the complete S7CommPlus packet with header and trailer.
    /// The packet format is: [magic(1)][opcode(1)][dataLen(2)][data...][magic(1)][opcode(1)][0x00][0x00]
    /// </summary>
    /// <returns>The complete S7CommPlus packet bytes</returns>
    public byte[] ToPacket()
    {
        var data = _data.ToArray();
        var packet = new byte[HeaderLength + data.Length + TrailerLength];

        // Header
        packet[0] = ProtocolMagic;
        packet[1] = _opcode;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)data.Length);

        // Data
        data.CopyTo(packet.AsSpan(HeaderLength));

        // Trailer
        packet[^4] = ProtocolMagic;
        packet[^3] = _opcode;
        // Last two bytes are already 0x00

        return packet;
    }

    public void Dispose()
    {
        _data.Dispose();
    }
}
