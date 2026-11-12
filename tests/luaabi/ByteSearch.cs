using System;

public static class ByteSearch
{
    public static long Find(byte[] haystack, byte[] needle, int start)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
        {
            return -1;
        }

        byte first = needle[0];
        int last = haystack.Length - needle.Length;

        for (int i = start; i <= last; i++)
        {
            if (haystack[i] != first)
            {
                continue;
            }

            int j = 1;
            while (j < needle.Length && haystack[i + j] == needle[j])
            {
                j++;
            }

            if (j == needle.Length)
            {
                return i;
            }
        }

        return -1;
    }
}
