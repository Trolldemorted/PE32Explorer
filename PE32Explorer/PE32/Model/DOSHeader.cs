using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record DOSHeader(byte[] Data)
{
    public int e_lfanew => BitConverter.ToInt32(this.Data.AsSpan(0x3C, 4));

    public static async Task<DOSHeader> Parse(Stream inputStream, CancellationToken cancelToken)
    {
        var dosHeaderData = new byte[StructSize];
        await inputStream.ReadExactlyAsync(dosHeaderData, cancelToken);
        return new DOSHeader(dosHeaderData);
    }

    public static int StructSize => 0x40;
}
