using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record SectionHeader(
    byte[] Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint SizeOfRawData,
    uint PointerToRawData,
    uint PointerToRelocations,
    uint PointerToLinenumbers,
    ushort NumberOfRelocations,
    ushort NumberOfLinenumbers,
    uint Characteristics)
{
    public async static Task<SectionHeader> Parse(Stream inputStream, CancellationToken cancelToken)
    {
        var sectionHeaderData = new byte[StructSize];
        await inputStream.ReadExactlyAsync(sectionHeaderData, cancelToken);
        byte[] name = sectionHeaderData[0x00..0x08];
        uint virtualSize = BitConverter.ToUInt32(sectionHeaderData.AsSpan()[0x08..0x0C]);
        uint virtualAddress = BitConverter.ToUInt32(sectionHeaderData.AsSpan()[0x0C..0x10]);
        uint sizeOfRawData = BitConverter.ToUInt32(sectionHeaderData.AsSpan()[0x10..0x14]);
        uint pointerToRawData = BitConverter.ToUInt32(sectionHeaderData.AsSpan()[0x14..0x18]);
        uint pointerToRelocations = BitConverter.ToUInt32(sectionHeaderData.AsSpan()[0x18..0x1C]);
        uint pointerToLinenumbers = BitConverter.ToUInt32(sectionHeaderData.AsSpan()[0x1C..0x20]);
        ushort numberOfRelocations = BitConverter.ToUInt16(sectionHeaderData.AsSpan()[0x20..0x22]);
        ushort numberOfLinenumbers = BitConverter.ToUInt16(sectionHeaderData.AsSpan()[0x22..0x24]);
        uint characteristics = BitConverter.ToUInt32(sectionHeaderData.AsSpan()[0x24..0x28]);

        return new SectionHeader(
            name,
            virtualSize,
            virtualAddress,
            sizeOfRawData,
            pointerToRawData,
            pointerToRelocations,
            pointerToLinenumbers,
            numberOfRelocations,
            numberOfLinenumbers,
            characteristics);
    }

    public static int StructSize => 0x28;
}
