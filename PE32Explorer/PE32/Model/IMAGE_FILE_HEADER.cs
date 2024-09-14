﻿using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_FILE_HEADER
{
    public ushort Machine { get; set; }
    public ushort NumberOfSections { get; set; }
    public uint TimeDateStamp { get; set; }
    public uint PointerToSymbolTable { get; set; }
    public uint NumberOfSymbols { get; set; }
    public ushort SizeOfOptionalHeader { get; set; }
    public ushort Characteristics { get; set; }

    public IMAGE_FILE_HEADER(
        ushort machine,
        ushort numberOfSections,
        uint timeDateStamp,
        uint pointerToSymbolTable,
        uint numberOfSymbols,
        ushort sizeOfOptionalHeader,
        ushort characteristics) => (
            Machine,
            NumberOfSections,
            TimeDateStamp,
            PointerToSymbolTable,
            NumberOfSymbols,
            SizeOfOptionalHeader,
            Characteristics) = (machine,
            numberOfSections,
            timeDateStamp,
            pointerToSymbolTable,
            numberOfSymbols,
            sizeOfOptionalHeader,
            characteristics);
}
