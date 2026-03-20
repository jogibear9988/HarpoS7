using System.Text;

namespace HarpoS7.Packets;

/// <summary>
/// Parses a CreateObject response to extract the session ID, public key fingerprint,
/// and authentication challenge.
/// </summary>
public class CreateObjectResponse
{
    /// <summary>
    /// Offset of the session ID in the S7CommPlus payload.
    /// </summary>
    private const int SessionIdOffset = 0x10;

    /// <summary>
    /// Offset of the fingerprint length for PlcSim responses.
    /// </summary>
    private const int PlcSimFingerprintLengthOffset = 0x30;

    /// <summary>
    /// Offset of the fingerprint length for real PLC (S7-1200/S7-1500) responses.
    /// </summary>
    private const int RealPlcFingerprintLengthOffset = 0x28;

    /// <summary>
    /// The session ID assigned by the PLC.
    /// </summary>
    public uint SessionId { get; }

    /// <summary>
    /// The public key fingerprint string (e.g. "03:XXXX" or "00:XXXX").
    /// </summary>
    public string Fingerprint { get; }

    /// <summary>
    /// The 20-byte authentication challenge from the PLC.
    /// </summary>
    public byte[] Challenge { get; }

    /// <summary>
    /// Parses a CreateObject response from the raw S7CommPlus payload bytes.
    /// </summary>
    /// <param name="payload">The S7CommPlus payload (without TPKT/COTP framing)</param>
    /// <exception cref="InvalidOperationException">Thrown when the fingerprint cannot be found</exception>
    public CreateObjectResponse(ReadOnlySpan<byte> payload)
    {
        // Read session ID (VLQ-encoded at known offset)
        SessionId = Vlq.DecodeUInt32(payload[SessionIdOffset..], out _);

        // Try PlcSim fingerprint offset first, then real PLC offset
        Fingerprint = TryReadFingerprint(payload, PlcSimFingerprintLengthOffset)
                      ?? TryReadFingerprint(payload, RealPlcFingerprintLengthOffset)
                      ?? throw new InvalidOperationException(
                          "Could not find a valid public key fingerprint in the response");

        // Read the 20-byte challenge
        // The challenge offset depends on the device family
        var challengeOffset = Fingerprint.StartsWith("03:") ? 0x76 : 0x6E;
        Challenge = payload.Slice(challengeOffset, Constants.ChallengeLength).ToArray();
    }

    private static string? TryReadFingerprint(ReadOnlySpan<byte> payload, int lengthOffset)
    {
        if (lengthOffset >= payload.Length)
            return null;

        var fingerprintLength = Vlq.DecodeUInt32(payload[lengthOffset..], out var vlqLength);
        var valueOffset = lengthOffset + vlqLength;

        if (valueOffset + fingerprintLength > payload.Length)
            return null;

        var fingerprint = Encoding.UTF8.GetString(payload.Slice(valueOffset, (int)fingerprintLength));

        if (fingerprint.StartsWith("03:") || fingerprint.StartsWith("00:") || fingerprint.StartsWith("01:"))
            return fingerprint;

        return null;
    }
}
