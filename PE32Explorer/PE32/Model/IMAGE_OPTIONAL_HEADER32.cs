using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_OPTIONAL_HEADER32(byte[] Data, uint NumberOfRvaAndSizes, List<IMAGE_DATA_DIRECTORY> Directories);
