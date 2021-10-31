using System;
using System.Linq;

namespace DesEncryption
{
    public delegate void FeistelDoneCallback(int count, long left, long right);

    public enum DesKeyStrength
    {
        Strong,
        SemiWeak,
        Weak,
        Invalid
    }

    public static class Des
    {
        public static long Encrypt(long key, long plaintext, FeistelDoneCallback? feistelCallback = null)
        {
            ValidateKey(key);
            long[] roundKeys = Get16KeysForEachRound(key);

            return Encode(roundKeys, plaintext, feistelCallback);
        }

        private static void ValidateKey(long key)
        {
            var keyStrength = GetKeyStrength(key);

            if (keyStrength == DesKeyStrength.Invalid)
            {
                throw new ArgumentException(
                    "DES key should have odd number of 1 in each byte.");
            }
            if (keyStrength == DesKeyStrength.Weak)
            {
                throw new ArgumentException(
                    "DES key is weak.");
            }
        }

        private static long[] Get16KeysForEachRound(long key)
        {
            int[] tableToExtendKeyTo56Bits = DesTables.PC1;

            long extendedKey = Bits.Permute(key, 64, tableToExtendKeyTo56Bits);

            long partC = Bits.Subrange(extendedKey, 28, 28);
            long partD = Bits.Subrange(extendedKey, 0, 28);

            long[] roundKeys = new long[16];
            for (int i = 0; i < 16; i++)
            {
                int shiftLength = i == 0 || i == 1 || i == 8 || i == 15
                    ? 1
                    : 2;
                partC = Bits.CyclicShiftLeft(partC, 28, shiftLength);
                partD = Bits.CyclicShiftLeft(partD, 28, shiftLength);
                long combinedParts = Bits.Join(partC, partD, 28);

                int[] tableToTransposeRoundKeys = DesTables.PC2;
                roundKeys[i] = Bits.Permute(combinedParts, 56, tableToTransposeRoundKeys);
            }
            return roundKeys;
        }

        private static long Encode(long[] roundKeys, long plaintext, FeistelDoneCallback? feistelDoneCallback)
        {
            int[] initialPermutationTable = DesTables.IP;
            long initiallyPermuted = Bits.Permute(plaintext, 64, initialPermutationTable);
            long left = Bits.Subrange(initiallyPermuted, 32, 32);
            long right = Bits.Subrange(initiallyPermuted, 0, 32);

            feistelDoneCallback?.Invoke(0, left, right);

            for (int i = 0; i < 16; i++)
            {
                long roundKey = roundKeys[i];
                long previousLeft = left;
                long previousRight = right;
                left = previousRight;
                right = previousLeft ^ FeistelFunction(previousRight, roundKey);

                feistelDoneCallback?.Invoke(i + 1, left, right);
            }

            long combinedBack = Bits.Join(right, left, 32);
            int[] inversePermutation = DesTables.IPInverse;

            return Bits.Permute(combinedBack, 64, inversePermutation);
        }

        public static long Decrypt(long key, long ciphertext)
        {
            ValidateKey(key);
            long[] roundKeys = Get16KeysForEachRound(key);

            return Decode(roundKeys, ciphertext);
        }

        private static long Decode(long[] roundKeys, long ciphertext)
        {
            int[] initialPermutationTable = DesTables.IP;
            long initiallyPermuted = Bits.Permute(ciphertext, 64, initialPermutationTable);
            long left = Bits.Subrange(initiallyPermuted, 32, 32);
            long right = Bits.Subrange(initiallyPermuted, 0, 32);

            for (int i = 15; i >= 0; i--)
            {
                long roundKey = roundKeys[i];
                long previousLeft = left;
                long previousRight = right;
                left = previousRight;
                right = previousLeft ^ FeistelFunction(previousRight, roundKey);
            }

            long combinedBack = Bits.Join(right, left, 32);
            int[] inversePermutation = DesTables.IPInverse;

            return Bits.Permute(combinedBack, 64, inversePermutation);
        }

        private static long FeistelFunction(long data, long roundKey)
        {
            int[] bitSelectionTable = DesTables.E;
            long expandedData = Bits.Permute(data, 32, bitSelectionTable);
            long xorWithKey = expandedData ^ roundKey;

            var sixBitsBlocks = Enumerable.Range(0, 8)
                .Select(i => Bits.Subrange(xorWithKey, i * 6, 6))
                .Reverse();
            var fourBitBlocks = sixBitsBlocks
                .Select((b, i) =>
                {
                    long firstBit = Bits.Subrange(b, 5, 1);
                    long lastBit = Bits.Subrange(b, 0, 1);
                    long row = Bits.Join(firstBit, lastBit, 1);
                    long col = Bits.Subrange(b, 1, 4);
                    long coord = Bits.Join(row, col, 4);
                    int[][] substitutionBoxes = DesTables.S;
                    return (long)substitutionBoxes[i][coord];
                })
                .Reverse();

            var sBoxes = Bits.Join(fourBitBlocks, 4);

            int[] permutationTable = DesTables.P;
            long permutated32BitBlock = Bits.Permute(sBoxes, 32, permutationTable);
            return permutated32BitBlock;
        }

        public static DesKeyStrength GetKeyStrength(long key)
        {
            var bytesOfKey = BitConverter.GetBytes(key);
            if (!bytesOfKey.All(keyByte => Bits.CountOfOnes(keyByte).IsOdd()))
            {
                return DesKeyStrength.Invalid;
            }

            if (key == unchecked((long)0x0101010101010101)
                || key == unchecked((long)0xFEFEFEFEFEFEFEFE)
                || key == unchecked((long)0xE0E0E0E0F1F1F1F1)
                || key == unchecked((long)0x1F1F1F1F0E0E0E0E)
            )
            {
                return DesKeyStrength.Weak;
            }

            if (key == unchecked((long)0x011F011F010E010E)
                || key == unchecked((long)0x1F011F010E010E01)

                || key == unchecked((long)0x01E001E001F101F1)
                || key == unchecked((long)0xE001E001F101F101)

                || key == unchecked((long)0x01FE01FE01FE01FE)
                || key == unchecked((long)0xFE01FE01FE01FE01)

                || key == unchecked((long)0x1FE01FE00EF10EF1)
                || key == unchecked((long)0xE01FE01FF10EF10E)

                || key == unchecked((long)0x1FFE1FFE0EFE0EFE)
                || key == unchecked((long)0xFE1FFE1FFE0EFE0E)

                || key == unchecked((long)0xE0FEE0FEF1FEF1FE)
                || key == unchecked((long)0xFEE0FEE0FEF1FEF1)
            )
            {
                return DesKeyStrength.SemiWeak;
            }

            return DesKeyStrength.Strong;
        }
    }
}
