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
    uint Characteristics);
