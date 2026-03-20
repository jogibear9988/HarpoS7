using HarpoS7.PoC.Models;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.PoC.Packets;

/// <summary>
/// Parses a SetVarSubStreamed response from the PLC.
/// Extracts the status code indicating legitimation success/failure.
/// <para>
/// Response structure: [TPKT/COTP] [S7CommPlus Header] [Integrity] [Data with return value]
/// </para>
/// </summary>
public class SetVarSubStreamedResponse
{
    /// <summary>
    /// Offset to the return value field within the raw packet data.
    /// Located after TPKT+COTP(7) + S7CommPlus header(4) + integrity(33) + data marker(1) + opcode header(9).
    /// </summary>
    private const int ReturnValueOffset = 0x36;

    public EStatusCode StatusCode { get; set; }

    public SetVarSubStreamedResponse(ReadOnlySpan<byte> packet)
    {
        var returnValue = packet[ReturnValueOffset..].DecodeAsVlq64(out _);
        StatusCode = (EStatusCode)(int)(returnValue & 0b11111111_11111111);
    }
}