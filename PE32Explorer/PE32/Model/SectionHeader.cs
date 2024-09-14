using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record SectionHeader
{
    public required byte[] Name { get; set; }
    public required uint VirtualSize { get; set; }
    public required uint VirtualAddress { get; set; }
    public required uint SizeOfRawData { get; set; }
    public required uint PointerToRawData { get; set; }
    public required uint PointerToRelocations { get; set; }
    public required uint PointerToLinenumbers { get; set; }
    public required ushort NumberOfRelocations { get; set; }
    public required ushort NumberOfLinenumbers { get; set; }
    public required uint Characteristics { get; set; }
}
