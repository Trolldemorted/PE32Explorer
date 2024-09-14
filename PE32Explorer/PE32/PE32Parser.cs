using Microsoft.Extensions.Logging;
using PE32Explorer.PE32.Model;
using PE32Explorer.Util;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32;

internal class PE32Parser
{
    private readonly ILogger<PE32Parser> logger;

    public PE32Parser(ILogger<PE32Parser> logger)
    {
        this.logger = logger;
    }

    #region Read
    public PE32File ReadPE32File(ReadOnlySpan<byte> input)
    {
        this.logger.LogDebug("Reading PE32 File");
        var headerInput = input;
        var dosHeader = this.ReadDOSHeader(ref headerInput);
        var dosStub = this.ReadDOSStub(dosHeader.e_lfanew, ref headerInput);
        var imageNtHeaders32 = this.ReadImageNtHeaders32(ref headerInput);
        this.logger.LogDebug($"{imageNtHeaders32.FileHeader}");
        this.logger.LogDebug($"{imageNtHeaders32.OptionalHeader}");
        var importDirectory = imageNtHeaders32.OptionalHeader!.DataDirectory[1];
        this.logger.LogDebug($"importDirectory: {importDirectory.VirtualAddress:x}");
        var sectionTable = new List<SectionHeader>();
        for (var i = 0; i < imageNtHeaders32.FileHeader.NumberOfSections; i++)
        {
            var sectionHeader = this.ReadSectionHeader(ref headerInput);
            this.logger.LogDebug(
                $"Section {Encoding.UTF8.GetString(sectionHeader.Name).TrimEnd('\0')}:" +
                $" virtual={sectionHeader.VirtualAddress:X}-{sectionHeader.VirtualAddress + sectionHeader.VirtualSize:X}" +
                $" file={sectionHeader.PointerToRawData:X}-{sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData:X}" +
                $" relocs={sectionHeader.PointerToRelocations:X}" +
                $" characteristics={sectionHeader.Characteristics:X}");
            sectionTable.Add(sectionHeader);
        }

        var sections = new List<Section>();
        foreach (var sectionHeader in sectionTable)
        {
            var section = this.ReadSectionData(sectionHeader, ref input);
            sections.Add(section);
        }

        return new PE32File(dosHeader, dosStub, imageNtHeaders32, sections);
    }

    public DOSHeader ReadDOSHeader(ref ReadOnlySpan<byte> input)
    {
        this.logger.LogDebug("Reading DOS Header");
        return new DOSHeader(input.ReadBytes(DOSHeader.StructSize));
    }

    public DOSStub ReadDOSStub(int e_lfanew, ref ReadOnlySpan<byte> input)
    {
        this.logger.LogDebug("Reading DOS Stub");
        var size = e_lfanew - DOSHeader.StructSize;
        return new DOSStub(input.ReadBytes(size));
    }

    public IMAGE_NT_HEADERS32 ReadImageNtHeaders32(ref ReadOnlySpan<byte> input)
    {
        this.logger.LogDebug("Reading NT Headers");
        var signature = input.ReadUInt32LE();
        var fileHeader = this.ReadImageFileHeader(ref input);
        var optionalHeader = this.ReadImageOptionalHeader32(fileHeader.SizeOfOptionalHeader, ref input);
        return new IMAGE_NT_HEADERS32()
        {
            Signature = signature,
            FileHeader = fileHeader,
            OptionalHeader = optionalHeader!
        };
    }

    public IMAGE_FILE_HEADER ReadImageFileHeader(ref ReadOnlySpan<byte> input)
    {
        ushort machine = input.ReadUInt16LE();
        ushort numberOfSections = input.ReadUInt16LE();
        uint timeDateStamp = input.ReadUInt32LE();
        uint pointerToSymbolTable = input.ReadUInt32LE();
        uint numberOfSymbols = input.ReadUInt32LE();
        ushort sizeOfOptionalHeader = input.ReadUInt16LE();
        ushort characteristics = input.ReadUInt16LE();
        return new IMAGE_FILE_HEADER()
        {
            Machine = machine,
            NumberOfSections = numberOfSections,
            TimeDateStamp = timeDateStamp,
            PointerToSymbolTable = pointerToSymbolTable,
            NumberOfSymbols = numberOfSymbols,
            SizeOfOptionalHeader = sizeOfOptionalHeader,
            Characteristics = characteristics
        };
    }

    public IMAGE_OPTIONAL_HEADER32? ReadImageOptionalHeader32(int size, ref ReadOnlySpan<byte> input)
    {
        if (size == 0)
        {
            return null;
        }

        ushort magic = input.ReadUInt16LE();
        byte majorLinkerVersion = input.ReadByte();
        byte minorLinkerVersion = input.ReadByte();
        uint sizeOfCode = input.ReadUInt32LE();
        uint sizeOfInitializedData = input.ReadUInt32LE();
        uint sizeOfUninitializedData = input.ReadUInt32LE();
        uint addressOfEntryPoint = input.ReadUInt32LE();
        uint baseOfCode = input.ReadUInt32LE();
        uint baseOfData = input.ReadUInt32LE();
        uint imageBase = input.ReadUInt32LE();
        uint sectionAlignment = input.ReadUInt32LE();
        uint fileAlignment = input.ReadUInt32LE();
        ushort majorOperatingSystemVersion = input.ReadUInt16LE();
        ushort minorOperatingSystemVersion = input.ReadUInt16LE();
        ushort majorImageVersion = input.ReadUInt16LE();
        ushort minorImageVersion = input.ReadUInt16LE();
        ushort majorSubsystemVersion = input.ReadUInt16LE();
        ushort minorSubsystemVersion = input.ReadUInt16LE();
        uint win32VersionValue = input.ReadUInt32LE();
        uint sizeOfImage = input.ReadUInt32LE();
        uint sizeOfHeaders = input.ReadUInt32LE();
        uint checkSum = input.ReadUInt32LE();
        ushort subsystem = input.ReadUInt16LE();
        ushort dllCharacteristics = input.ReadUInt16LE();
        uint sizeOfStackReserve = input.ReadUInt32LE();
        uint sizeOfStackCommit = input.ReadUInt32LE();
        uint sizeOfHeapReserve = input.ReadUInt32LE();
        uint sizeOfHeapCommit = input.ReadUInt32LE();
        uint loaderFlags = input.ReadUInt32LE();
        uint numberOfRvaAndSizes = input.ReadUInt32LE();

        var directories = new List<IMAGE_DATA_DIRECTORY>();
        for (var i = 0; i < numberOfRvaAndSizes; i++)
        {
            directories.Add(this.ReadImageDataDirectory(ref input));
        }
        //TODO how to deal with excess data?

        return new IMAGE_OPTIONAL_HEADER32
        {
            Magic = magic,
            MajorLinkerVersion = majorLinkerVersion,
            MinorLinkerVersion = minorLinkerVersion,
            SizeOfCode = sizeOfCode,
            SizeOfInitializedData = sizeOfInitializedData,
            SizeOfUninitializedData = sizeOfUninitializedData,
            AddressOfEntryPoint = addressOfEntryPoint,
            BaseOfCode = baseOfCode,
            BaseOfData = baseOfData,
            ImageBase = imageBase,
            SectionAlignment = sectionAlignment,
            FileAlignment = fileAlignment,
            MajorOperatingSystemVersion = majorOperatingSystemVersion,
            MinorOperatingSystemVersion = minorOperatingSystemVersion,
            MajorImageVersion = majorImageVersion,
            MinorImageVersion = minorImageVersion,
            MajorSubsystemVersion = majorSubsystemVersion,
            MinorSubsystemVersion = minorSubsystemVersion,
            Win32VersionValue = win32VersionValue,
            SizeOfImage = sizeOfImage,
            SizeOfHeaders = sizeOfHeaders,
            CheckSum = checkSum,
            Subsystem = subsystem,
            DllCharacteristics = dllCharacteristics,
            SizeOfStackReserve = sizeOfStackReserve,
            SizeOfStackCommit = sizeOfStackCommit,
            SizeOfHeapReserve = sizeOfHeapReserve,
            SizeOfHeapCommit = sizeOfHeapCommit,
            LoaderFlags = loaderFlags,
            NumberOfRvaAndSizes = numberOfRvaAndSizes,
            DataDirectory = directories
        };
    }

    public IMAGE_DATA_DIRECTORY ReadImageDataDirectory(ref ReadOnlySpan<byte> input)
    {
        uint virtualAddress = input.ReadUInt32LE();
        uint size = input.ReadUInt32LE();

        return new IMAGE_DATA_DIRECTORY(virtualAddress, size);
    }

    public SectionHeader ReadSectionHeader(ref ReadOnlySpan<byte> input)
    {
        byte[] name = input.ReadBytes(0x08);
        uint virtualSize = input.ReadUInt32LE();
        uint virtualAddress = input.ReadUInt32LE();
        uint sizeOfRawData = input.ReadUInt32LE();
        uint pointerToRawData = input.ReadUInt32LE();
        uint pointerToRelocations = input.ReadUInt32LE();
        uint pointerToLinenumbers = input.ReadUInt32LE();
        ushort numberOfRelocations = input.ReadUInt16LE();
        ushort numberOfLinenumbers = input.ReadUInt16LE();
        uint characteristics = input.ReadUInt32LE();

        return new SectionHeader()
        {
            Name = name,
            VirtualSize = virtualSize,
            VirtualAddress = virtualAddress,
            SizeOfRawData = sizeOfRawData, 
            PointerToRawData = pointerToRawData,
            PointerToRelocations = pointerToRelocations,
            PointerToLinenumbers = pointerToLinenumbers,
            NumberOfRelocations = numberOfRelocations,
            NumberOfLinenumbers = numberOfLinenumbers,
            Characteristics = characteristics,
        };
    }

    public Section ReadSectionData(SectionHeader header, ref ReadOnlySpan<byte> input)
    {
        var data = input.Slice((int)header.PointerToRawData, (int)header.SizeOfRawData).ToArray();
        return new Section()
        {
            Name = Encoding.UTF8.GetString(header.Name).TrimEnd('\0'),
            VirtualSize = header.VirtualSize,
            VirtualAddress = header.VirtualAddress,
            Characteristics = header.Characteristics,
            Data = data,
        };
    }
    #endregion

    #region Write
    public async Task WritePE32File(PE32File pe32File, Stream outputStream, CancellationToken cancelToken)
    {
        this.logger.LogDebug("Writing PE32 File");

        // Make our changes
        pe32File.Sections.Add(new Section()
        {
            Name = ".mod",
            VirtualSize = 0x10000,
            VirtualAddress = MathUtil.RoundUp(0x2F86D4, pe32File.NtHeaders32.OptionalHeader!.SectionAlignment),
            Characteristics = 0xC0000040,
            Data = new byte[0x1000],
        });

        // Write DOS header
        await outputStream.WriteAsync(pe32File.DOSHeader.Data, cancelToken); //TODO properly reflect changes
        await outputStream.WriteAsync(pe32File.DOSStub.Data, cancelToken); //TODO properly reflect changes

        // Write PE32 header
        var pe32Position = outputStream.Position;
        pe32File.NtHeaders32.FileHeader.NumberOfSections = (ushort)pe32File.Sections.Count;
        var calculatedSizeOfImage = (uint)(pe32File.Sections.Sum(e => MathUtil.RoundUp(e.VirtualSize, 4096)) + MathUtil.RoundUp(pe32File.Sections.Count * 40, 4096));
        pe32File.NtHeaders32.OptionalHeader.SizeOfImage = calculatedSizeOfImage;
        await this.WriteImageNtHeaders32(pe32File.NtHeaders32, outputStream, cancelToken);

        // Write sections
        await this.WriteSectionTable(pe32File.Sections, outputStream, pe32File.NtHeaders32.OptionalHeader!.SectionAlignment, pe32File.NtHeaders32.OptionalHeader!.FileAlignment, cancelToken);
        await this.WriteSectionData(pe32File.Sections, outputStream, pe32File.NtHeaders32.OptionalHeader!.FileAlignment, cancelToken);
    }

    public async Task WriteImageNtHeaders32(IMAGE_NT_HEADERS32 ntHeaders32, Stream outputStream, CancellationToken cancelToken)
    {
        await outputStream.WriteAsync(BitConverter.GetBytes(ntHeaders32.Signature), cancelToken);
        await this.WriteImageFileHeader(ntHeaders32.FileHeader, outputStream, cancelToken);
        await this.WriteImageOptionalHeader(ntHeaders32.OptionalHeader, outputStream, cancelToken);
    }

    public async Task WriteImageFileHeader(IMAGE_FILE_HEADER fileHeader, Stream outputStream, CancellationToken cancelToken)
    {
        await outputStream.WriteAsync(BitConverter.GetBytes(fileHeader.Machine), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(fileHeader.NumberOfSections), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(fileHeader.TimeDateStamp), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(fileHeader.PointerToSymbolTable), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(fileHeader.NumberOfSymbols), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(fileHeader.SizeOfOptionalHeader), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(fileHeader.Characteristics), cancelToken);
    }

    public async Task WriteImageOptionalHeader(IMAGE_OPTIONAL_HEADER32? optionalHeader32, Stream outputStream, CancellationToken cancelToken)
    {
        if (optionalHeader32 is null)
        {
            return;
        }

        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.Magic), cancelToken);
        await outputStream.WriteAsync(new byte[] { optionalHeader32.MajorLinkerVersion }, cancelToken);
        await outputStream.WriteAsync(new byte[] { optionalHeader32.MinorLinkerVersion }, cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfCode), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfInitializedData), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfUninitializedData), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.AddressOfEntryPoint), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.BaseOfCode), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.BaseOfData), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.ImageBase), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SectionAlignment), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.FileAlignment), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.MajorOperatingSystemVersion), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.MinorOperatingSystemVersion), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.MajorImageVersion), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.MinorImageVersion), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.MajorSubsystemVersion), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.MinorSubsystemVersion), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.Win32VersionValue), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfImage), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfHeaders), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.CheckSum), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.Subsystem), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.DllCharacteristics), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfStackReserve), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfStackCommit), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfHeapReserve), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.SizeOfHeapCommit), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.LoaderFlags), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(optionalHeader32.NumberOfRvaAndSizes), cancelToken);

        foreach (var dataDirectory in optionalHeader32.DataDirectory)
        {
            await WriteImageDataDirectory(dataDirectory, outputStream, cancelToken);
        }
    }

    public async Task WriteImageDataDirectory(IMAGE_DATA_DIRECTORY dataDirectory, Stream outputStream, CancellationToken cancelToken)
    {
        await outputStream.WriteAsync(BitConverter.GetBytes(dataDirectory.VirtualAddress), cancelToken);
        await outputStream.WriteAsync(BitConverter.GetBytes(dataDirectory.Size), cancelToken);
    }

    public async Task WriteSectionTable(List<Section> sections, Stream outputStream, uint sectionAlignment, uint fileAlignment, CancellationToken cancelToken)
    {
        this.logger.LogDebug("Writing section table to 0x{:X}", outputStream.Position);
        var filePos = (uint)(outputStream.Position + sections.Count * 40);
        foreach (var section in sections)
        {
            // Calculate filePos
            filePos = MathUtil.RoundUp(filePos, fileAlignment);

            this.logger.LogDebug("Writing section {:X} pointing to 0x{:X}", section.Name, filePos);

            // Build name
            var name = new byte[8];
            Encoding.UTF8.GetBytes(section.Name).CopyTo(name.AsSpan());

            // Sanity checks
            if (section.Data.Length % fileAlignment != 0)
            {
                throw new InvalidOperationException();
            }
            if (filePos % fileAlignment != 0)
            {
                throw new InvalidOperationException();
            }
            if (section.VirtualAddress % sectionAlignment != 0)
            {
                throw new InvalidOperationException();
            }

            await outputStream.WriteAsync(name, cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(section.VirtualSize), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(section.VirtualAddress), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(section.Data.Length), cancelToken); // SizeOfRawData
            await outputStream.WriteAsync(BitConverter.GetBytes(filePos), cancelToken); // PointerToRawData
            await outputStream.WriteAsync(BitConverter.GetBytes((uint)1), cancelToken); // PointerToRelocations
            await outputStream.WriteAsync(BitConverter.GetBytes((uint)2), cancelToken); // PointerToLinenumbers
            await outputStream.WriteAsync(BitConverter.GetBytes((ushort)3), cancelToken); // NumberOfRelocations
            await outputStream.WriteAsync(BitConverter.GetBytes((ushort)4), cancelToken); // NumberOfLinenumbers
            await outputStream.WriteAsync(BitConverter.GetBytes(section.Characteristics), cancelToken);

            filePos += (uint)section.Data.Length;
        }
    }

    public async Task WriteSectionData(List<Section> sections, Stream outputStream, uint fileAlignment, CancellationToken cancelToken)
    {
        this.logger.LogDebug("Writing section data to {:X}", outputStream.Position);
        var filePos = outputStream.Position;
        var paddingSize = Util.MathUtil.RoundUp(outputStream.Position, fileAlignment) - outputStream.Position;
        var padding = new byte[paddingSize];
        await outputStream.WriteAsync(padding, cancelToken);
        foreach (var section in sections)
        {
            await outputStream.WriteAsync(section.Data, cancelToken);
            paddingSize = Util.MathUtil.RoundUp(outputStream.Position, fileAlignment) - outputStream.Position;
            padding = new byte[paddingSize];
            await outputStream.WriteAsync(padding, cancelToken);
        }
    }
    #endregion
}
