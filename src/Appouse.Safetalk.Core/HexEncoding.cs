namespace Appouse.Safetalk;

/// <summary>
/// Allocation-free hexadecimal helpers shared by all target frameworks.
/// </summary>
internal static class HexEncoding
{
    /// <summary>
    /// Encodes bytes as lower-case hexadecimal.
    /// </summary>
    public static string ToLowerHex(ReadOnlySpan<byte> bytes)
    {
#if NET9_0_OR_GREATER
        return Convert.ToHexStringLower(bytes);
#else
        ReadOnlySpan<char> alphabet = "0123456789abcdef";
        Span<char> chars = bytes.Length <= 128 ? stackalloc char[bytes.Length * 2] : new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = alphabet[bytes[i] >> 4];
            chars[(i * 2) + 1] = alphabet[bytes[i] & 0xF];
        }

        return new string(chars);
#endif
    }

    /// <summary>
    /// Decodes a hexadecimal string (either case) whose length must exactly match <paramref name="destination"/>.
    /// </summary>
    /// <returns><see langword="false"/> when the length is wrong or a non-hexadecimal character is found.</returns>
    public static bool TryDecode(ReadOnlySpan<char> hex, Span<byte> destination)
    {
        if (hex.Length != destination.Length * 2)
        {
            return false;
        }

        for (int i = 0; i < destination.Length; i++)
        {
            int high = FromHexChar(hex[i * 2]);
            int low = FromHexChar(hex[(i * 2) + 1]);
            if ((high | low) < 0)
            {
                return false;
            }

            destination[i] = (byte)((high << 4) | low);
        }

        return true;
    }

    private static int FromHexChar(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };
}
