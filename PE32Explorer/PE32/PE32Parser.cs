using Microsoft.Extensions.Logging;
using PE32Explorer.PE32.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
    public async Task<PE32File> ReadPE32File(Stream inputStream, CancellationToken cancelToken)
    {
        this.logger.LogDebug("Parsing PE32 File");
        var dosHeader = await DOSHeader.Parse(inputStream, cancelToken);
        var dosStub = await DOSStub.Parse(dosHeader.e_lfanew, inputStream, cancelToken);
        var imageNtHeaders32 = await IMAGE_NT_HEADERS32.Parse(inputStream, cancelToken);
        Debug.WriteLine($"{imageNtHeaders32.FileHeader}");
        Debug.WriteLine($"{imageNtHeaders32.OptionalHeader}");
        var importDirectory = imageNtHeaders32.OptionalHeader!.Directories[1];
        Debug.WriteLine($"importDirectory: {importDirectory.VirtualAddress:x}");
        var sectionTable = new List<SectionHeader>();
        for (var i = 0; i < imageNtHeaders32.FileHeader.NumberOfSections; i++)
        {
            var section = await SectionHeader.Parse(inputStream, cancelToken);
            Debug.WriteLine($"VirtualAddress: {section.VirtualAddress:X}");
            sectionTable.Add(section);
        }

        using var data = new MemoryStream();
        await inputStream.CopyToAsync(data, cancelToken);
        return new PE32File(dosHeader, dosStub, imageNtHeaders32, sectionTable, data.ToArray());
    }
    #endregion

    #region Write
    public async Task WritePE32File(PE32File pe32File, Stream outputStream, CancellationToken cancelToken)
    {
        this.logger.LogDebug("Write PE32 File");
        await outputStream.WriteAsync(pe32File.DOSHeader.Data, cancelToken);
        await outputStream.WriteAsync(pe32File.DOSStub.Data, cancelToken);
        await this.WriteImageNtHeaders32(pe32File.NtHeaders32, outputStream, cancelToken);
        await this.WriteSectionTable(pe32File.SectionTable, outputStream, pe32File.NtHeaders32.FileHeader.FileAlignment, cancelToken);
        await outputStream.WriteAsync(pe32File.Data, cancelToken);
    }

    public async Task WriteImageNtHeaders32(IMAGE_NT_HEADERS32 ntHeaders32, Stream outputStream, CancellationToken cancelToken)
    {
        await outputStream.WriteAsync(BitConverter.GetBytes(ntHeaders32.Signature));
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
