using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record PE32File(
    DOSHeader DOSHeader,
    DOSStub DOSStub,
    IMAGE_NT_HEADERS32 NtHeaders32,
    List<Section> Sections);
