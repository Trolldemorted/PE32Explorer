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
using static System.Runtime.InteropServices.JavaScript.JSType;

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
        var dosHeader = this.ReadDOSHeader(ref input);
        var dosStub = this.ReadDOSStub(dosHeader.e_lfanew, ref input);
        var imageNtHeaders32 = this.ReadImageNtHeaders32(ref input);
        Debug.WriteLine($"{imageNtHeaders32.FileHeader}");
        Debug.WriteLine($"{imageNtHeaders32.OptionalHeader}");
        var importDirectory = imageNtHeaders32.OptionalHeader!.DataDirectory[1];
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
        return new IMAGE_NT_HEADERS32(signature, fileHeader, optionalHeader);
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
        return new IMAGE_FILE_HEADER(
            machine,
            numberOfSections,
            timeDateStamp,
            pointerToSymbolTable,
            numberOfSymbols,
            sizeOfOptionalHeader,
            characteristics);
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

        return new IMAGE_OPTIONAL_HEADER32(
            magic,
            majorLinkerVersion,
            minorLinkerVersion,
            sizeOfCode,
            sizeOfInitializedData,
            sizeOfUninitializedData,
            addressOfEntryPoint,
            baseOfCode,
            baseOfData,
            imageBase,
            sectionAlignment,
            fileAlignment,
            majorOperatingSystemVersion,
            minorOperatingSystemVersion,
            majorImageVersion,
            minorImageVersion,
            majorSubsystemVersion,
            minorSubsystemVersion,
            win32VersionValue,
            sizeOfImage,
            sizeOfHeaders,
            checkSum,
            subsystem,
            dllCharacteristics,
            sizeOfStackReserve,
            sizeOfStackCommit,
            sizeOfHeapReserve,
            sizeOfHeapCommit,
            loaderFlags,
            numberOfRvaAndSizes,
            directories);
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
        this.logger.LogDebug("Writing PE32 File");
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
