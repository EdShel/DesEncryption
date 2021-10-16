using DesEncryption;

long key = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001;
long data = 0b00000001_00100011_01000101_01100111_10001001_10101011_11001101_11101111;
long result = Des.Encrypt(key, data);
Console.WriteLine("Key:    0x" + Convert.ToString(key, 16).PadLeft(16, '0'));
Console.WriteLine("Data:   0x" + Convert.ToString(data, 16).PadLeft(16, '0'));
Console.WriteLine("Result: 0x" + Convert.ToString(result, 16).PadLeft(16, '0'));

long decrypted = Des.Decrypt(key, result);
Console.WriteLine("Decrypt:0x" + Convert.ToString(decrypted, 16).PadLeft(16, '0'));
