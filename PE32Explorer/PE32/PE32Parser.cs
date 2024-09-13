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
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Windows.Storage.Streams;

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
        this.logger.LogDebug("Parsing PE32 File");
        var dosHeader = this.ReadDOSHeader(ref input);
        var dosStub = this.ReadDOSStub(dosHeader.e_lfanew, ref input);
        var imageNtHeaders32 = this.ReadImageNtHeaders32(ref input);
        Debug.WriteLine($"{imageNtHeaders32.FileHeader}");
        Debug.WriteLine($"{imageNtHeaders32.OptionalHeader}");
        var importDirectory = imageNtHeaders32.OptionalHeader!.Directories[1];
        Debug.WriteLine($"importDirectory: {importDirectory.VirtualAddress:x}");
        var sectionTable = new List<SectionHeader>();
        for (var i = 0; i < imageNtHeaders32.FileHeader.NumberOfSections; i++)
        {
            var section = this.ReadSectionHeader(ref input);
            Debug.WriteLine($"VirtualAddress: {section.VirtualAddress:X}");
            sectionTable.Add(section);
        }

        return new PE32File(dosHeader, dosStub, imageNtHeaders32, sectionTable, input.ToArray());
    }

    public DOSHeader ReadDOSHeader(ref ReadOnlySpan<byte> input)
    {
        this.logger.LogDebug("Read DOS Header");
        return new DOSHeader(input.ReadBytes(DOSHeader.StructSize));
    }

    public DOSStub ReadDOSStub(int e_lfanew, ref ReadOnlySpan<byte> input)
    {
        this.logger.LogDebug("Read DOS Stub");
        var size = e_lfanew - DOSHeader.StructSize;
        return new DOSStub(input.ReadBytes(size));
    }

    public IMAGE_NT_HEADERS32 ReadImageNtHeaders32(ref ReadOnlySpan<byte> input)
    {
        var signature = input.ReadUInt32LE();
        var fileHeader = this.ReadImageFileHeader(ref input);
        var optionalHeader = this.ReadImageOptionalHeader32(fileHeader.SizeOfOptionalHeader, ref input);
        return new IMAGE_NT_HEADERS32(signature, fileHeader, optionalHeader);
    }

    public IMAGE_FILE_HEADER ReadImageFileHeader(ref ReadOnlySpan<byte> input)
    {
        byte[] fileHeaderData = input.ReadBytes(0x14);
        return new IMAGE_FILE_HEADER(fileHeaderData);
    }

    public IMAGE_OPTIONAL_HEADER32? ReadImageOptionalHeader32(int size, ref ReadOnlySpan<byte> input)
    {
        if (size == 0)
        {
            return null;
        }

        var optionalHeaderData = input.ReadBytes(size);
        var numberOfRvaAndSizes = BitConverter.ToUInt32(optionalHeaderData.AsSpan(0x5C, 4));

        var directories = new List<IMAGE_DATA_DIRECTORY>();
        var dataDirectoryData = optionalHeaderData[0x60..];
        for (var i = 0; i < numberOfRvaAndSizes; i++)
        {
            directories.Add(IMAGE_DATA_DIRECTORY.Parse(dataDirectoryData));
            dataDirectoryData = dataDirectoryData[IMAGE_DATA_DIRECTORY.StructSize..];
        }

        return new IMAGE_OPTIONAL_HEADER32(optionalHeaderData, numberOfRvaAndSizes, directories);
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
    #endregion

    #region Write
    public async Task WritePE32File(PE32File pe32File, Stream outputStream, CancellationToken cancelToken)
    {
        this.logger.LogDebug("Write PE32 File");
        await outputStream.WriteAsync(pe32File.DOSHeader.Data, cancelToken); //TODO properly reflect changes
        await outputStream.WriteAsync(pe32File.DOSStub.Data, cancelToken); //TODO properly reflect changes
        await this.WriteImageNtHeaders32(pe32File.NtHeaders32, outputStream, cancelToken);
        await this.WriteSectionTable(pe32File.SectionTable, outputStream, 0, cancelToken); //TODO proper file alignment
        await outputStream.WriteAsync(pe32File.Data, cancelToken);
    }

    public async Task WriteImageNtHeaders32(IMAGE_NT_HEADERS32 ntHeaders32, Stream outputStream, CancellationToken cancelToken)
    {
        await outputStream.WriteAsync(BitConverter.GetBytes(ntHeaders32.Signature), cancelToken);
        await this.WriteImageFileHeader(ntHeaders32.FileHeader, outputStream, cancelToken);
        await this.WriteImageOptionalHeader(ntHeaders32.OptionalHeader, outputStream, cancelToken);
    }

    public async Task WriteImageFileHeader(IMAGE_FILE_HEADER fileHeader, Stream outputStream, CancellationToken cancelToken)
    {
        // TODO properly reflect changes
        await outputStream.WriteAsync(fileHeader.Data, cancelToken);
    }

    public async Task WriteImageOptionalHeader(IMAGE_OPTIONAL_HEADER32? optionalHeader32, Stream outputStream, CancellationToken cancelToken)
    {
        if (optionalHeader32 is null)
        {
            return;
        }

        // TODO properly reflect changes
        await outputStream.WriteAsync(optionalHeader32.Data, cancelToken);
    }

    public async Task WriteSectionTable(List<SectionHeader> sectionHeaders, Stream outputStream, uint fileAlignment, CancellationToken cancelToken)
    {
        this.logger.LogDebug("Writing section table to {:X}", outputStream.Position);
        foreach (var sectionHeader in sectionHeaders)
        {
            // TODO: Validate SizeOfRawData, PointerToRawData being a multiple of FileAlignment
            await outputStream.WriteAsync(sectionHeader.Name, cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.VirtualSize), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.VirtualAddress), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.SizeOfRawData), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.PointerToRawData), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.PointerToRelocations), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.PointerToLinenumbers), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.NumberOfRelocations), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.NumberOfLinenumbers), cancelToken);
            await outputStream.WriteAsync(BitConverter.GetBytes(sectionHeader.Characteristics), cancelToken);
        }
    }
    #endregion
}
