using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_OPTIONAL_HEADER32
{
    public required ushort Magic { get; set; }
    public required byte MajorLinkerVersion { get; set; }
    public required byte MinorLinkerVersion { get; set; }
    public required uint SizeOfCode { get; set; }
    public required uint SizeOfInitializedData { get; set; }
    public required uint SizeOfUninitializedData { get; set; }
    public required uint AddressOfEntryPoint { get; set; }
    public required uint BaseOfCode { get; set; }
    public required uint BaseOfData { get; set; }
    public required uint ImageBase { get; set; }
    public required uint SectionAlignment { get; set; }
    public required uint FileAlignment { get; set; }
    public required ushort MajorOperatingSystemVersion { get; set; }
    public required ushort MinorOperatingSystemVersion { get; set; }
    public required ushort MajorImageVersion { get; set; }
    public required ushort MinorImageVersion { get; set; }
    public required ushort MajorSubsystemVersion { get; set; }
    public required ushort MinorSubsystemVersion { get; set; }
    public required uint Win32VersionValue { get; set; }
    public required uint SizeOfImage { get; set; }
    public required uint SizeOfHeaders { get; set; }
    public required uint CheckSum { get; set; }
    public required ushort Subsystem { get; set; }
    public required ushort DllCharacteristics { get; set; }
    public required uint SizeOfStackReserve { get; set; }
    public required uint SizeOfStackCommit { get; set; }
    public required uint SizeOfHeapReserve { get; set; }
    public required uint SizeOfHeapCommit { get; set; }
    public required uint LoaderFlags { get; set; }
    public required uint NumberOfRvaAndSizes { get; set; }
    public required List<IMAGE_DATA_DIRECTORY> DataDirectory { get; set; }
}
