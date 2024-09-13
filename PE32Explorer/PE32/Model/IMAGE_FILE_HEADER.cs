using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_FILE_HEADER(byte[] Data)
{
    public int NumberOfSections => BitConverter.ToUInt16(this.Data.AsSpan(2, 2));
    public int SizeOfOptionalHeader => BitConverter.ToUInt16(this.Data.AsSpan(0x10, 2));

    public static async Task<IMAGE_FILE_HEADER> Parse(Stream inputStream, CancellationToken cancelToken)
    {
        var imageNtHeaders32Data = new byte[0x14];
        await inputStream.ReadExactlyAsync(imageNtHeaders32Data, cancelToken);
        return new IMAGE_FILE_HEADER(imageNtHeaders32Data);
    }
}
