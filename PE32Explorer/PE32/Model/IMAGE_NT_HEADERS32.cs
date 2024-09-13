using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Devices.Printers.Extensions;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_NT_HEADERS32(uint Signature, IMAGE_FILE_HEADER FileHeader, IMAGE_OPTIONAL_HEADER32? OptionalHeader);
