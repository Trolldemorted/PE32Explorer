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
    uint FirstThunk)
{
    public static async Task<IMAGE_IMPORT_DESCRIPTOR?> Parse(Stream inputStream, CancellationToken cancelToken)
    {
        var imageImportDescriptorData = new byte[StructSize];
        var imageImportDescriptor = imageImportDescriptorData.AsMemory();
        await inputStream.ReadExactlyAsync(imageImportDescriptor, cancelToken);
        var anonymous = BitConverter.ToUInt32(imageImportDescriptor.Span[0x00..0x04]);
        var timeDateStamp = BitConverter.ToUInt32(imageImportDescriptor.Span[0x04..0x08]);
        var forwarderChain = BitConverter.ToUInt32(imageImportDescriptor.Span[0x08..0x0C]);
        var name = BitConverter.ToUInt32(imageImportDescriptor.Span[0x0C..0x10]);
        var firstThunk = BitConverter.ToUInt32(imageImportDescriptor.Span[0x10..0x14]);
        return new IMAGE_IMPORT_DESCRIPTOR(
            anonymous,
            timeDateStamp,
            forwarderChain,
            name,
            firstThunk);
    }

    public static int StructSize => 0x14;
}
