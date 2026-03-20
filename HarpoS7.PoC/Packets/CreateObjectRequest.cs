using System.Buffers.Binary;
using System.Text;
using HarpoS7.PoC.Protocol;

namespace HarpoS7.PoC.Packets;

/// <summary>
/// Builds a CreateObject request for the S7 Comm Plus protocol.
/// This replaces the hardcoded binary blob that was previously used to create
/// a session object on the PLC.
/// <para>
/// Packet structure (after TPKT/COTP):
/// <list type="bullet">
///   <item>S7CommPlus Header: [0x72] [PDU=0x01] [DataLength:2]</item>
///   <item>Opcode Header: [0x31 Request] [Reserved:2] [Function=0x04CA] [Reserved:2] [Sequence:2]</item>
///   <item>Object Reference: [ObjectRef:4] [Separator:1] [DataAreaLength:4] [Qualifier:7]</item>
///   <item>Server Session Object: Attributes (name, adapter, access, app, host, etc.)</item>
///   <item>Subscription Container Object: Attributes (name)</item>
///   <item>End of Objects: [0xA2 0xA2] [Qualifier:4]</item>
///   <item>S7CommPlus Trailer: [0x72] [PDU=0x01] [0x00 0x00]</item>
/// </list>
/// </para>
/// </summary>
public class CreateObjectRequest
{
    /// <summary>Name of the session (e.g. "ServerSession_1C9C381")</summary>
    public string SessionName { get; set; } = "ServerSession_1C9C381";

    /// <summary>Network adapter info string</summary>
    public string AdapterInfo { get; set; } = "A0:::6.0::ASIX AX88179 USB 3.0 to Gigabit Ethernet Adapter.TCPIP.1";

    /// <summary>Access mode string</summary>
    public string AccessMode { get; set; } = "Read Write";

    /// <summary>Application name string</summary>
    public string ApplicationName { get; set; } = "HMI RT OMS+";

    /// <summary>Host name string</summary>
    public string HostName { get; set; } = "YourHost";

    /// <summary>Access level integer</summary>
    public byte AccessLevel { get; set; } = 0x02;

    /// <summary>Read/Write mode description</summary>
    public string ReadWriteMode { get; set; } = "Read/Write tags";

    /// <summary>Subscription container name</summary>
    public string SubscriptionContainerName { get; set; } = "SubscriptionContainer";

    // Well-known attribute IDs (VLQ encoded constants from the protocol)
    private static readonly byte[] AttrIdObjectName = [0x81, 0x69]; // ID = 233 (ObjectVariableTypeName)
    private static readonly byte[] AttrIdAdapterInfo = [0x82, 0x21]; // ID = 289
    private static readonly byte[] AttrIdAccessMode = [0x82, 0x28]; // ID = 296
    private static readonly byte[] AttrIdAppName = [0x82, 0x29]; // ID = 297
    private static readonly byte[] AttrIdHostName = [0x82, 0x2A]; // ID = 298
    private static readonly byte[] AttrIdAccessLevel = [0x82, 0x2B]; // ID = 299
    private static readonly byte[] AttrIdTimestamp = [0x82, 0x2C]; // ID = 300
    private static readonly byte[] AttrIdRwMode = [0x82, 0x2D]; // ID = 301

    // Server session class ID (VLQ: 0x82 0x1F → ID 287)
    private static readonly byte[] SessionClassId = [0x82, 0x1F];
    // Subscription container class ID (VLQ: 0x81 0x7F → ID 255)
    private static readonly byte[] SubscriptionClassId = [0x81, 0x7F];

    // Object qualifier prefix (class D3 = standard object container)
    private static readonly byte[] SessionObjectQualifier = [0x00, 0x00, 0x00, 0xD3];
    private static readonly byte[] SubscriptionObjectQualifier = [0x00, 0x00, 0x00, 0xD3];

    // Timestamp value (VLQ-encoded, from original capture)
    private static readonly byte[] TimestampValue = [0x01, 0xC9, 0xC3, 0x81];

    /// <summary>
    /// Write the CreateObject request to the given stream.
    /// The stream should handle TPKT/COTP framing (e.g. CotpStream).
    /// </summary>
    public void WriteTo(Stream stream)
    {
        var payload = BuildPayload();
        stream.Write(payload);
    }

    /// <summary>
    /// Build the complete S7CommPlus packet (without TPKT/COTP).
    /// </summary>
    public byte[] BuildPayload()
    {
        // Build the data area (between header and trailer)
        var dataArea = BuildDataArea();

        var totalLength = S7CommPlusConstants.HeaderLength + dataArea.Length + S7CommPlusConstants.TrailerLength;
        var packet = new byte[totalLength];

        // Write header
        var header = new S7CommPlusHeader
        {
            PduType = S7CommPlusConstants.PduTypeConnect,
            DataLength = (ushort)dataArea.Length
        };
        header.WriteTo(packet);

        // Write data area
        dataArea.CopyTo(packet.AsSpan(S7CommPlusConstants.HeaderLength));

        // Write trailer
        header.WriteTrailerTo(packet.AsSpan(totalLength - S7CommPlusConstants.TrailerLength));

        return packet;
    }

    private byte[] BuildDataArea()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        // Opcode header
        Span<byte> opcodeBytes = stackalloc byte[S7CommPlusOpcodeHeader.SerializedLength];
        var opcodeHeader = new S7CommPlusOpcodeHeader
        {
            Opcode = S7CommPlusConstants.OpcodeRequest,
            Function = S7CommPlusConstants.FunctionCreateObject,
            SequenceNumber = 0x0001
        };
        opcodeHeader.WriteTo(opcodeBytes);
        bw.Write(opcodeBytes);

        // Object reference area
        // (This section contains reference IDs and qualifiers used by the PLC
        //  to manage the session object. Values are from protocol analysis.)
        bw.Write((uint)0x00000120); // object reference
        bw.Write((byte)0x36);       // separator/tag
        WriteObjectReferenceArea(bw);

        // === First Object: Server Session ===
        WriteStartOfObject(bw, SessionObjectQualifier, SessionClassId);
        WriteStringAttribute(bw, AttrIdObjectName, SessionName);
        WriteStringAttribute(bw, AttrIdAdapterInfo, AdapterInfo);
        WriteStringAttribute(bw, AttrIdAccessMode, AccessMode);
        WriteStringAttribute(bw, AttrIdAppName, ApplicationName);
        WriteStringAttribute(bw, AttrIdHostName, HostName);
        WriteUDIntAttribute(bw, AttrIdAccessLevel, AccessLevel);
        WriteTimestampAttribute(bw, AttrIdTimestamp, TimestampValue);
        WriteStringAttribute(bw, AttrIdRwMode, ReadWriteMode);

        // === Second Object: Subscription Container ===
        WriteStartOfObject(bw, SubscriptionObjectQualifier, SubscriptionClassId);
        WriteStringAttribute(bw, AttrIdObjectName, SubscriptionContainerName);

        // End of objects
        bw.Write(S7CommPlusConstants.TagEndOfObject); // 0xA2
        bw.Write(S7CommPlusConstants.TagEndOfObject); // 0xA2
        bw.Write((uint)0x00000000); // end qualifier

        bw.Flush();
        return ms.ToArray();
    }

    private static void WriteObjectReferenceArea(BinaryWriter bw)
    {
        // Data area length and qualifier (from protocol analysis)
        // These bytes define the object creation parameters
        bw.Write(new byte[] { 0x00, 0x00, 0x01, 0x1D }); // data area info
        bw.Write(new byte[] { 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }); // object qualifier
    }

    private static void WriteStartOfObject(BinaryWriter bw, byte[] objectQualifier, byte[] classId)
    {
        bw.Write(S7CommPlusConstants.TagStartOfObject); // 0xA1
        bw.Write(objectQualifier);
        bw.Write(classId);
        bw.Write((byte)0x00); // object flags
        bw.Write((byte)0x00); // object flags
    }

    private static void WriteStringAttribute(BinaryWriter bw, byte[] attributeId, string value)
    {
        bw.Write(S7CommPlusConstants.TagAttribute); // 0xA3
        bw.Write(attributeId);
        bw.Write((byte)0x00); // attribute flags
        bw.Write(S7CommPlusConstants.DataTypeWString); // 0x15

        // String length as VLQ
        Span<byte> vlqBuf = stackalloc byte[5];
        var vlqLen = ((ulong)Encoding.UTF8.GetByteCount(value)).EncodeAsVlq(vlqBuf);
        bw.Write(vlqBuf[..vlqLen]);

        // String content
        bw.Write(Encoding.UTF8.GetBytes(value));
    }

    private static void WriteUDIntAttribute(BinaryWriter bw, byte[] attributeId, uint value)
    {
        bw.Write(S7CommPlusConstants.TagAttribute); // 0xA3
        bw.Write(attributeId);
        bw.Write((byte)0x00); // attribute flags
        bw.Write(S7CommPlusConstants.DataTypeUDInt); // 0x04
        bw.Write((byte)value);
    }

    private static void WriteTimestampAttribute(BinaryWriter bw, byte[] attributeId, byte[] timestampValue)
    {
        bw.Write(S7CommPlusConstants.TagAttribute); // 0xA3
        bw.Write(attributeId);
        bw.Write((byte)0x00); // attribute flags
        bw.Write(S7CommPlusConstants.DataTypeTimestamp); // 0x12
        bw.Write(timestampValue);
    }
}
