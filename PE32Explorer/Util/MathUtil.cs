using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PE32Explorer.Util;

internal class MathUtil
{
    public static long RoundUp(long value, uint multiple)
    {
        return (value + multiple - 1) / multiple * multiple;
    }

    public static uint RoundUp(uint value, uint multiple)
    {
        return (value + multiple - 1) / multiple * multiple;
    }
}
