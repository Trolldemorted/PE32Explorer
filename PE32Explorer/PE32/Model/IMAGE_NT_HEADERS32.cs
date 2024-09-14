using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Devices.Printers.Extensions;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_NT_HEADERS32
{
    public uint Signature { get; set; }
    public IMAGE_FILE_HEADER FileHeader { get; set; }
    public IMAGE_OPTIONAL_HEADER32 OptionalHeader { get; set; }

    public IMAGE_NT_HEADERS32(uint signature, IMAGE_FILE_HEADER fileHeader, IMAGE_OPTIONAL_HEADER32 optionalHeader)
    { //TODO use better constructor syntax
        this.Signature = signature;
        this.FileHeader = fileHeader;
        this.OptionalHeader = optionalHeader;
    }
}