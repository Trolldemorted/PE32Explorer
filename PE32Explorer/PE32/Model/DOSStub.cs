using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record DOSStub(byte[] Data)
{
    public static async Task<DOSStub> Parse(int e_lfanew, Stream inputStream, CancellationToken cancelToken)
    {
        var dosHeaderData = new byte[e_lfanew - DOSHeader.StructSize];
        await inputStream.ReadExactlyAsync(dosHeaderData, cancelToken);
        return new DOSStub(dosHeaderData);
    }
}
