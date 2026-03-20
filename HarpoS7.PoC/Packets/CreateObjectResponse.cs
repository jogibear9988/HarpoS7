using System.Buffers.Binary;
using System.Text;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.PoC.Packets;

/// <summary>
/// Parses the CreateObject response from the PLC.
/// Dynamically extracts the session ID, public key fingerprint, and challenge
/// by scanning the response data instead of relying on hardcoded offsets.
/// This fixes compatibility with different PLC models and firmware versions
/// (see: https://github.com/bonk-dev/HarpoS7/issues/18).
/// </summary>
public class CreateObjectResponse
{
    /// <summary>The session object ID assigned by the PLC (VLQ decoded)</summary>
    public uint SessionId { get; }

    /// <summary>
    /// The public key fingerprint string (e.g. "03:AABBCCDD..." or "00:AABBCCDD...").
    /// This identifies which public key family the PLC uses.
    /// </summary>
    public string Fingerprint { get; }

    /// <summary>The 20-byte authentication challenge from the PLC</summary>
    public byte[] Challenge { get; }

    private const int ChallengeLength = 20;

    /// <summary>
    /// Parse a CreateObject response from S7CommPlus data.
    /// The data should NOT include TPKT/COTP headers (use CotpStream to strip them).
    /// If reading from a raw TCP stream, the data includes TPKT+COTP and the
    /// <paramref name="rawTcpOffset"/> should be set to 7.
    /// </summary>
    /// <param name="data">The packet data</param>
    /// <param name="rawTcpOffset">
    /// Offset to add for raw TCP data that includes TPKT/COTP headers (default: 0).
    /// Set to 7 when reading from raw TCP stream without CotpStream.
    /// </param>
    public CreateObjectResponse(ReadOnlySpan<byte> data, int rawTcpOffset = 0)
    {
        var s7Data = data[rawTcpOffset..];

        // Validate S7CommPlus header
        var header = S7CommPlusHeader.Parse(s7Data);

        // Parse the opcode header (after S7CommPlus header)
        var payloadStart = S7CommPlusConstants.HeaderLength;
        var opcodeHeader = S7CommPlusOpcodeHeader.Parse(s7Data[payloadStart..]);

        if (opcodeHeader.Function != S7CommPlusConstants.FunctionCreateObject)
            throw new InvalidDataException(
                $"Expected CreateObject function (0x{S7CommPlusConstants.FunctionCreateObject:X4}), " +
                $"got 0x{opcodeHeader.Function:X4}");

        // Extract session ID - it's VLQ-encoded after the opcode header + some reserved bytes.
        // The exact offset varies by PLC model, so we scan a range of positions.
        SessionId = ExtractSessionId(s7Data);

        // Scan for fingerprint string (dynamic - no hardcoded offset)
        Fingerprint = FindFingerprint(s7Data)
            ?? throw new InvalidDataException(
                "Could not find a valid fingerprint in the CreateObject response. " +
                "The fingerprint should be a string like 'XX:AABBCCDD...' where XX is the key family.");

        // Scan for the 20-byte challenge array (appears after the fingerprint)
        Challenge = FindChallenge(s7Data, Fingerprint)
            ?? throw new InvalidDataException(
                "Could not find the 20-byte challenge in the CreateObject response.");
    }

    /// <summary>
    /// Extract the session ID by trying VLQ decode at multiple candidate offsets.
    /// Different PLC models place the session ID at slightly different positions
    /// after the opcode header.
    /// </summary>
    private static uint ExtractSessionId(ReadOnlySpan<byte> s7Data)
    {
        // After S7CommPlus header (4) + opcode header (9) = offset 13
        // Then there may be 0-4 bytes of return value/reserved data before the session ID.
        // We try offsets 13 through 18 to find a valid session ID.
        for (int offset = 13; offset <= 18 && offset + 5 <= s7Data.Length; offset++)
        {
            var value = Vlq.DecodeAsVlq32(s7Data[offset..], out var len);
            // A valid session ID should be non-zero and fit in a reasonable VLQ length
            if (value != 0 && len >= 1 && len <= 5)
            {
                return value;
            }
        }

        // Session ID 0x00000000 can occur with some PLC models (see issue #18)
        // In that case, return 0
        return 0;
    }

    /// <summary>
    /// Scan the response data for a fingerprint string.
    /// The fingerprint has the format "XX:HHHHHH..." where XX is a 2-digit hex number
    /// (the key family) followed by colon and hex characters.
    /// </summary>
    internal static string? FindFingerprint(ReadOnlySpan<byte> data)
    {
        // Scan for the pattern: [string data type 0x15] [VLQ length] [ASCII: XX:...]
        // We look for the data type marker followed by string content matching the fingerprint format.
        for (int i = 0; i < data.Length - 5; i++)
        {
            // Look for WString data type marker (0x15)
            if (data[i] != S7CommPlusConstants.DataTypeWString)
                continue;

            // Try to decode the VLQ string length
            if (i + 1 >= data.Length)
                continue;

            var stringLength = Vlq.DecodeAsVlq32(data[(i + 1)..], out var vlqLen);
            if (stringLength < 4 || stringLength > 200)
                continue;

            var stringStart = i + 1 + vlqLen;
            if (stringStart + (int)stringLength > data.Length)
                continue;

            // Check if this string matches the fingerprint pattern: "XX:..."
            var stringBytes = data.Slice(stringStart, (int)stringLength);
            if (stringBytes.Length >= 3 &&
                IsHexDigit(stringBytes[0]) &&
                IsHexDigit(stringBytes[1]) &&
                stringBytes[2] == (byte)':')
            {
                var candidate = Encoding.UTF8.GetString(stringBytes);
                if (IsValidFingerprint(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Find the 20-byte challenge array in the response data.
    /// The challenge appears after the fingerprint, typically as an OctetString
    /// (data type 0x05) with length 20.
    /// </summary>
    internal static byte[]? FindChallenge(ReadOnlySpan<byte> data, string fingerprint)
    {
        // Find the position of the fingerprint string in the data
        var fingerprintBytes = Encoding.UTF8.GetBytes(fingerprint);
        int fingerprintEnd = -1;

        for (int i = 0; i <= data.Length - fingerprintBytes.Length; i++)
        {
            if (data.Slice(i, fingerprintBytes.Length).SequenceEqual(fingerprintBytes))
            {
                fingerprintEnd = i + fingerprintBytes.Length;
                break;
            }
        }

        if (fingerprintEnd < 0)
            return null;

        // Scan forward from the fingerprint end for a 20-byte array.
        // Look for OctetString (0x05) or Blob (0x14) with length = 20.
        for (int i = fingerprintEnd; i < data.Length - ChallengeLength - 1; i++)
        {
            if (data[i] == S7CommPlusConstants.DataTypeOctetString ||
                data[i] == S7CommPlusConstants.DataTypeBlob)
            {
                if (i + 1 >= data.Length)
                    continue;

                var len = Vlq.DecodeAsVlq32(data[(i + 1)..], out var vlqLen);
                if (len == ChallengeLength && i + 1 + vlqLen + ChallengeLength <= data.Length)
                {
                    return data.Slice(i + 1 + vlqLen, ChallengeLength).ToArray();
                }
            }
        }

        // Fallback: Try to find any 20-byte blob after the fingerprint using raw scan.
        // The challenge bytes are preceded by a VLQ-encoded length of 20 (0x14).
        for (int i = fingerprintEnd; i < data.Length - ChallengeLength - 1; i++)
        {
            var len = Vlq.DecodeAsVlq32(data[i..], out var vlqLen);
            if (len == ChallengeLength && vlqLen == 1 && i + vlqLen + ChallengeLength <= data.Length)
            {
                return data.Slice(i + vlqLen, ChallengeLength).ToArray();
            }
        }

        return null;
    }

    private static bool IsHexDigit(byte b) =>
        (b >= (byte)'0' && b <= (byte)'9') ||
        (b >= (byte)'A' && b <= (byte)'F') ||
        (b >= (byte)'a' && b <= (byte)'f');

    /// <summary>
    /// Validate that a string looks like a valid public key fingerprint.
    /// Format: "XX:HHHH..." where XX is 2 hex digits and the rest are hex digits.
    /// </summary>
    internal static bool IsValidFingerprint(string s)
    {
        if (s.Length < 4 || s[2] != ':')
            return false;

        // First two chars must be hex digits
        if (!IsHexDigit((byte)s[0]) || !IsHexDigit((byte)s[1]))
            return false;

        // Remaining chars after "XX:" must all be hex digits
        for (int i = 3; i < s.Length; i++)
        {
            if (!IsHexDigit((byte)s[i]))
                return false;
        }

        // Must have an even number of hex digits after the prefix
        return (s.Length - 3) % 2 == 0 && s.Length > 3;
    }
}
