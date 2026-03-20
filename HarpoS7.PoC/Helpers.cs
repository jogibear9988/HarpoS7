using System.Globalization;

namespace HarpoS7.PoC;

public static class Helpers
{
    public static void PrintBuffer(ReadOnlyMemory<byte> buffer)
    {
        var span = buffer.Span;
        
        Console.Write("[");
        for (var i = 0; i < span.Length; ++i)
        {
            Console.Write("0x");
            Console.Write(span[i].ToString("X2"));

            if (i < span.Length - 1)
            {
                Console.Write(", ");
            }
        }
        
        Console.WriteLine("]");
    }

    /// <summary>
    /// Parse a fingerprint string and reverse the byte order.
    /// Supports any 2-digit hex prefix (e.g. "00:", "01:", "03:", etc.)
    /// </summary>
    public static void ParseAndReverseBytes(string fingerprint, Span<byte> destination)
    {
        if (fingerprint.Length < 4 || fingerprint[2] != ':')
        {
            throw new Exception($"Invalid fingerprint format: expected 'XX:...' but got '{fingerprint}'");
        }

        // Validate the prefix is hex digits
        if (!IsHexDigit(fingerprint[0]) || !IsHexDigit(fingerprint[1]))
        {
            throw new Exception($"Invalid fingerprint prefix: '{fingerprint[..2]}' is not a valid hex number");
        }

        var hexPart = fingerprint[3..];

        // I didn't see this happen, but let's better be safe than sorry
        if (hexPart.Length % 2 != 0)
        {
            hexPart = '0' + hexPart;
        }

        if (destination.Length < hexPart.Length / 2)
        {
            throw new ArgumentException($"Destination too small (need at least: {hexPart.Length / 2}, got: {destination.Length})",
                nameof(destination));
        }

        var j = 0;
        for (var i = hexPart.Length - 1; i >= 0; i -= 2)
        {
            var b = byte.Parse($"{hexPart[i - 1]}{hexPart[i]}", NumberStyles.HexNumber);
            destination[j++] = b;
        } 
    }

    public static void UseColor(Action action, ConsoleColor color)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = color;
        action();
        Console.ForegroundColor = original;
    }

    private static bool IsHexDigit(char c) =>
        (c >= '0' && c <= '9') ||
        (c >= 'A' && c <= 'F') ||
        (c >= 'a' && c <= 'f');
}