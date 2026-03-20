using System.Buffers.Binary;

namespace HarpoS7;

/// <summary>
/// Provides methods for encoding and decoding Variable-Length Quantity (VLQ) numbers
/// used in the S7CommPlus protocol.
/// </summary>
public static class Vlq
{
    /// <summary>
    /// Decodes a VLQ-encoded 32-bit unsigned integer from the given byte span.
    /// </summary>
    /// <param name="bytes">The source bytes</param>
    /// <param name="length">The number of bytes consumed</param>
    /// <returns>The decoded value</returns>
    public static uint DecodeUInt32(ReadOnlySpan<byte> bytes, out int length)
    {
        uint value = 0U;
        int index = 0;
        byte vlqPartValue;

        do
        {
            value <<= 7;
            vlqPartValue = bytes[index++];
            value |= (byte)(vlqPartValue & 0b0111_1111);
        } while ((vlqPartValue & 0b1000_0000) != 0 && index < 5);

        length = index;
        return value;
    }

    /// <summary>
    /// Decodes a VLQ-encoded 64-bit unsigned integer from the given byte span.
    /// </summary>
    /// <param name="bytes">The source bytes</param>
    /// <param name="length">The number of bytes consumed</param>
    /// <returns>The decoded value</returns>
    public static ulong DecodeUInt64(ReadOnlySpan<byte> bytes, out int length)
    {
        ulong value = 0UL;
        int index = 0;
        byte vlqPartValue;

        do
        {
            value <<= 7;
            vlqPartValue = bytes[index++];
            value |= (byte)(vlqPartValue & 0b0111_1111);
        } while ((vlqPartValue & 0b1000_0000) != 0 && index < 8);

        if (index >= 8 && bytes[index] != 0)
        {
            value <<= 8;
            value |= bytes[index++];
        }

        length = index;
        return value;
    }

    /// <summary>
    /// Encodes a 64-bit unsigned integer as a VLQ number into the destination span.
    /// </summary>
    /// <param name="value">The value to encode</param>
    /// <param name="destination">The destination buffer (must be at least 9 bytes)</param>
    /// <returns>The number of bytes written</returns>
    public static int Encode(ulong value, Span<byte> destination)
    {
        if (value == 0x00UL)
        {
            destination[0] = 0x00;
            return 1;
        }

        const int vlqBufferLength = sizeof(ulong) + 1;

        Span<byte> vlqSpan = stackalloc byte[vlqBufferLength];

        byte vlqEncodedPart;
        int index = 0;

        ulong remainingValue = value;
        const ulong lastOctetMask = (0xFFUL << ((vlqBufferLength - 2) * 8));

        bool fullVlq = false;
        if ((value & lastOctetMask) != 0)
        {
            // This value will be encoded as a 9 byte VLQ
            fullVlq = true;

            vlqEncodedPart = (byte)remainingValue;
            vlqSpan[^++index] = vlqEncodedPart;
            remainingValue >>= 8;
        }

        while (remainingValue > 0)
        {
            vlqEncodedPart = (byte)(remainingValue & 0b0111_1111);
            vlqEncodedPart |= 0b1000_0000;

            vlqSpan[^++index] = vlqEncodedPart;
            remainingValue >>= 7;
        }

        if (!fullVlq)
        {
            // Reset the VLQ bit on the least significant octet
            vlqSpan[^1] &= 0b0111_1111;
        }

        vlqSpan[(vlqBufferLength - index)..].CopyTo(destination);
        return index;
    }
}
