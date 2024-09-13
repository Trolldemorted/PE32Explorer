using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_DATA_DIRECTORY(uint VirtualAddress, uint Size)
{
    public static IMAGE_DATA_DIRECTORY Parse(ReadOnlyMemory<byte> data)
    {
        uint virtualAddress = BitConverter.ToUInt32(data.Span[0..4]);
        uint size = BitConverter.ToUInt32(data.Span[4..8]);

        return new IMAGE_DATA_DIRECTORY(virtualAddress, size);
    }

    public static int StructSize => 0x08;
}
