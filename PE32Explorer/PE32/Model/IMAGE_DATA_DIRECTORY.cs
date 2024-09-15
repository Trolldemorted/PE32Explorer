using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_DATA_DIRECTORY
{
    public required uint VirtualAddress { get; set; }
    public required uint Size { get; set; }
}
