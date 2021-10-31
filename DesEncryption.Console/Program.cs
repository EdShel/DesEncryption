using DesEncryption;

Test(
    key: 0x133457799BBCDFF1,
    data: 0x0123456789ABCDEF,
    expectedResult: unchecked((long)0x85E813540F0AB405)
);
Test(
    key: 0x0E329232EA6D0D73,
    data: unchecked((long)0x8787878787878787),
    expectedResult: 0
);

void Test(long key, long data, long expectedResult)
{
    Console.WriteLine("Key:    0x" + Convert.ToString(key, 16).PadLeft(16, '0'));
    Console.WriteLine("Data:   0x" + Convert.ToString(data, 16).PadLeft(16, '0'));

    long result = Des.Encrypt(key, data);
    Console.WriteLine("Result: 0x" + Convert.ToString(result, 16).PadLeft(16, '0'));
    if (result != expectedResult)
    {
        throw new Exception($"Result is wrong: {Convert.ToString(result, 16)} != {Convert.ToString(expectedResult, 16)}");
    }

    long decrypted = Des.Decrypt(key, result);
    Console.WriteLine("Decrypt:0x" + Convert.ToString(decrypted, 16).PadLeft(16, '0'));
    if (decrypted != data)
    {
        throw new Exception($"Decrypted is wrong: {Convert.ToString(decrypted, 16)} != {Convert.ToString(data, 16)}");
    }
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("OK");
    Console.ForegroundColor = ConsoleColor.Gray;
}