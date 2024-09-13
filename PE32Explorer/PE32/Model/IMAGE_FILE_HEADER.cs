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
}
