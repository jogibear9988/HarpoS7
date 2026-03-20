namespace HarpoS7.PoC.Protocol;

/// <summary>
/// Constants for the S7 Comm Plus protocol.
/// Derived from the Wireshark S7CommPlus dissector:
/// https://sourceforge.net/p/s7commwireshark/code/HEAD/tree/trunk/src/s7comm_plus/
/// </summary>
public static class S7CommPlusConstants
{
    /// <summary>S7 Comm Plus protocol identifier byte</summary>
    public const byte ProtocolId = 0x72;

    // PDU Types (first byte after protocol ID)
    /// <summary>Initial connection setup (e.g. CreateObject)</summary>
    public const byte PduTypeConnect = 0x01;
    /// <summary>Data exchange (e.g. SetMultiVariables)</summary>
    public const byte PduTypeData = 0x02;
    /// <summary>Data with integrity verification (e.g. GetVarSubStreamed, SetVarSubStreamed)</summary>
    public const byte PduTypeDataWithIntegrity = 0x03;

    // Opcodes (within payload)
    public const byte OpcodeRequest = 0x31;
    public const byte OpcodeResponse = 0x32;
    public const byte OpcodeNotification = 0x33;

    // Function codes
    public const ushort FunctionCreateObject = 0x04CA;
    public const ushort FunctionDeleteObject = 0x04D2;
    public const ushort FunctionGetMultiVariables = 0x04F2;
    public const ushort FunctionSetMultiVariables = 0x0542;
    public const ushort FunctionSetVarSubStreamed = 0x057C;
    public const ushort FunctionGetVarSubStreamed = 0x0586;

    // Tag element identifiers
    public const byte TagStartOfObject = 0xA1;
    public const byte TagEndOfObject = 0xA2;
    public const byte TagAttribute = 0xA3;

    // Data type identifiers (used in attribute values)
    public const byte DataTypeNull = 0x00;
    public const byte DataTypeBool = 0x01;
    public const byte DataTypeUSInt = 0x02;
    public const byte DataTypeUInt = 0x03;
    public const byte DataTypeUDInt = 0x04;
    public const byte DataTypeOctetString = 0x05;
    public const byte DataTypeTimestamp = 0x12;
    public const byte DataTypeBoolArray = 0x13;
    public const byte DataTypeBlob = 0x14;
    public const byte DataTypeWString = 0x15;

    // Integrity (PDU type 3)
    public const byte IntegrityPartId = 0x20;
    public const int IntegrityValueLength = 32; // HMAC-SHA256

    // Data part marker after integrity
    public const byte DataPartId = 0x8B;

    // Header/trailer sizes
    /// <summary>Proto(1) + PDU(1) + DataLength(2)</summary>
    public const int HeaderLength = 4;
    /// <summary>Proto(1) + PDU(1) + Padding(2)</summary>
    public const int TrailerLength = 4;
}
