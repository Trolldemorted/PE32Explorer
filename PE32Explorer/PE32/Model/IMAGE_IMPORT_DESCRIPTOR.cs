using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_IMPORT_DESCRIPTOR
{
    public required uint Anonymous { get; set; }
    public required uint TimeDateStamp { get; set; }
    public required uint ForwarderChain { get; set; }
    public required uint Name { get; set; }
    public required uint FirstThunk { get; set; }
}