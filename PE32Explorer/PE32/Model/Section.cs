using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PE32Explorer.PE32.Model;

record Section
{
    public required string Name { get; set; }
    public required uint VirtualSize { get; set; }
    public required uint VirtualAddress { get; set; }
    public required uint Characteristics { get; set; }
    public required byte[] Data { get; set; }
}
