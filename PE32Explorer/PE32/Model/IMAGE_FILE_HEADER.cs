using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_FILE_HEADER(
    ushort Machine,
    ushort NumberOfSections,
    uint TimeDateStamp,
    uint PointerToSymbolTable,
    uint NumberOfSymbols,
    ushort SizeOfOptionalHeader,
    ushort Characteristics);
