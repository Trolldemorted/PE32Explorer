using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

internal record IMAGE_IMPORT_DESCRIPTOR(
    uint Anonymous,
    uint TimeDateStamp,
    uint ForwarderChain,
    uint Name,
    uint FirstThunk);