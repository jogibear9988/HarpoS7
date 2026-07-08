using HarpoS7.Integrity;

namespace HarpoS7.Tests.Integrity;

public class HarpoCrc32Tests
{
    [Test]
    public void TestCrc32String()
    {
        string text = "Tag_12";
        var crc = new HarpoCrc32();

        crc.Update(text);

        Assert.That(crc.Result, Is.EqualTo(0x0CDF926DU));
    }

    [Test]
    [TestCase("TestStruct", "TestSInt", Typecode.SInt, 0xC0069460U)]
    [TestCase("TestStruct", "TestBool", Typecode.Bool, 0xED3879EFU)]
    [TestCase("TestStruct", "TestUSInt", Typecode.USInt, 0x23AA4F7AU)]
    [TestCase("TestStruct", "TestWord", Typecode.Word, 0x90E66202U)]
    [TestCase("TestStruct", "TestInt", Typecode.Int, 0x69083814U)]
    [TestCase("TestStruct", "TestUInt", Typecode.UInt, 0xA36B6156U)]
    [TestCase("TestStruct", "TestDWord", Typecode.DWord, 0x9D833E43U)]
    [TestCase("TestStruct", "TestDInt", Typecode.DInt, 0x90D51BAAU)]
    [TestCase("TestStruct", "TestUDInt", Typecode.UDInt, 0xC5AA9276U)]
    [TestCase("TestStruct", "TestReal", Typecode.Real, 0x28EF064DU)]
    [TestCase("TestStruct", "TestLInt", Typecode.LInt, 0x91DAEA45U)]
    [TestCase("TestStruct", "TestULInt", Typecode.ULInt, 0x7276315FU)]
    [TestCase("TestStruct", "TestLReal", Typecode.LReal, 0x3F809E29U)]
    public void TestCrc32V2_StructFields(string structName, string fieldName, Typecode typecode, uint expectedCrc)
    {
        // Struct parent
        // Name + StructTypeCode(0x11)
        var structCrc = new HarpoCrc32();
        structCrc.Update(structName + '\x11');

        var finalCrc = new HarpoCrc32();
        finalCrc.UpdateWith(structCrc.Result);
        finalCrc.UpdateWith(0x89); // Parent.Child delimiter

        var itemCrc = new HarpoCrc32();
        itemCrc.Update(fieldName); // Child name
        itemCrc.UpdateWith((byte)typecode);

        finalCrc.UpdateWith(itemCrc.Result);
        Assert.That(finalCrc.Result, Is.EqualTo(expectedCrc));
    }

    // scope: S71500; target: Default
    // TypesafeCRCProviderr; Siemens.Automation.DomainServices
    public enum Typecode : byte
    {
        Bool = 0x01,
        Byte = 0x02,
        Char = 0x03,
        Word = 0x04,
        Int = 0x05,
        DWord = 0x06,
        DInt = 0x07,
        Real = 0x08,
        Date = 0x09,
        TimeOfDay = 0x0A,
        Time = 0x0B,
        S5Time = 0x0C,
        DateAndTime = 0x0E,
        Array = 0x10,
        Struct = 0x11,
        String = 0x13,
        LReal = 0x30,
        ULInt = 0x31,
        LInt = 0x32,
        LWord = 0x33,
        USInt = 0x34,
        UInt = 0x35,
        UDInt = 0x36,
        SInt = 0x37,
        WChar = 0x3D,
        WString = 0x3E,
        LTime = 0x40,
        LTimeOfDay = 0x41
    }
}
