using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

record Section
{
    public Section(byte[] data, SectionHeader header) => (Data, Header) = (data, header);

    public byte[] Data { get; set; }
    public SectionHeader Header { get; set; }
}
