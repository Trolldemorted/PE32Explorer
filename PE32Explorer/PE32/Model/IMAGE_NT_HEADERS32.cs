using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Devices.Printers.Extensions;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_NT_HEADERS32(uint Signature, IMAGE_FILE_HEADER FileHeader, IMAGE_OPTIONAL_HEADER32? OptionalHeader)
{
    public static async Task<IMAGE_NT_HEADERS32> Parse(Stream inputStream, CancellationToken cancelToken)
    {
        var signatureData = new byte[4];
        await inputStream.ReadExactlyAsync(signatureData, cancelToken);
        var signature = BitConverter.ToUInt32(signatureData);

        var fileHeader = await IMAGE_FILE_HEADER.Parse(inputStream, cancelToken);

        var optionalHeader = await IMAGE_OPTIONAL_HEADER32.Parse(fileHeader.SizeOfOptionalHeader, inputStream, cancelToken);

        return new IMAGE_NT_HEADERS32(signature, fileHeader, optionalHeader);
    }
}
