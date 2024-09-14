using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PE32Explorer.Util;

internal static class ReadOnlySpanExtensions
{
    public static byte[] ReadBytes(ref this ReadOnlySpan<byte> buffer, int count)
    {
        var value = buffer[0..count].ToArray();
        buffer = buffer[count..];
        return value;
    }

    public static byte ReadByte(ref this ReadOnlySpan<byte> buffer)
    {
        var value = buffer[0];
        buffer = buffer[1..];
        return value;
    }

    public static int ReadInt32LE(ref this ReadOnlySpan<byte> buffer)
    {
        var value = BinaryPrimitives.ReadInt32LittleEndian(buffer);
        buffer = buffer[4..];
        return value;
    }

    public static ushort ReadUInt16LE(ref this ReadOnlySpan<byte> buffer)
    {
        var value = BinaryPrimitives.ReadUInt16LittleEndian(buffer);
        buffer = buffer[2..];
        return value;
    }

    public static uint ReadUInt32LE(ref this ReadOnlySpan<byte> buffer)
    {
        var value = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        buffer = buffer[4..];
        return value;
    }
}
