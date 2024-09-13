using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_OPTIONAL_HEADER32(byte[] Data, uint NumberOfRvaAndSizes, List<IMAGE_DATA_DIRECTORY> Directories)
{
    public static async Task<IMAGE_OPTIONAL_HEADER32?> Parse(int size, Stream inputStream, CancellationToken cancelToken)
    {
        if (size == 0)
        {
            return null;
        }

        var optionalHeaderData = new byte[size];
        await inputStream.ReadExactlyAsync(optionalHeaderData, cancelToken);

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
}
