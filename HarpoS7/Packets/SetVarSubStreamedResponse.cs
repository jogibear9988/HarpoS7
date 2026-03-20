namespace HarpoS7.Packets;

/// <summary>
/// Parses a SetVarSubStreamed response packet to extract the legitimation status code.
/// </summary>
public class SetVarSubStreamedResponse
{
    private const int ReturnValueOffset = 0x36;

    /// <summary>
    /// The legitimation status code from the response.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// Creates a new response parser from the raw packet bytes.
    /// The packet bytes should be the S7CommPlus payload (without TPKT/COTP framing).
    /// </summary>
    /// <param name="packet">The raw packet bytes</param>
    public SetVarSubStreamedResponse(ReadOnlySpan<byte> packet)
    {
        var returnValue = Vlq.DecodeUInt64(packet[ReturnValueOffset..], out _);
        StatusCode = (int)(returnValue & 0b11111111_11111111);
    }
}
