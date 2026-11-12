using System;

public static class Checksums
{
    public static uint Crc32(byte[] data, int offset, int length, uint polynomial)
    {
        uint crc = 0xFFFFFFFFu;

        for (int i = 0; i < length; i++)
        {
            crc ^= data[offset + i];

            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }

    public static ulong Crc64(byte[] data, int offset, int length, ulong polynomial)
    {
        ulong crc = 0xFFFFFFFFFFFFFFFFul;

        for (int i = 0; i < length; i++)
        {
            crc ^= data[offset + i];

            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFFFFFFFFFul;
    }

    public static byte[] Le(uint value)
    {
        return BitConverter.GetBytes(value);
    }

    public static byte[] Le(ulong value)
    {
        return BitConverter.GetBytes(value);
    }

    public static byte[] Be(uint value)
    {
        byte[] b = BitConverter.GetBytes(value);
        Array.Reverse(b);
        return b;
    }

    public static byte[] Be(ulong value)
    {
        byte[] b = BitConverter.GetBytes(value);
        Array.Reverse(b);
        return b;
    }
}
