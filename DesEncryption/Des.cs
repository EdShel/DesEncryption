namespace DesEncryption
{
    public static class Des
    {
        public static long Encrypt(long key, long plaintext)
        {
            ValidateKey(key);
            long[] roundKeys = Get16KeysForEachRound(key);

            return Encode(roundKeys, plaintext);
        }

        private static void ValidateKey(long key)
        {
            var bytesOfKey = BitConverter.GetBytes(key);
            if (!bytesOfKey.All(keyByte => Bits.CountOfOnes(keyByte).IsOdd()))
            {
                throw new ArgumentException(
                    "DES key should have odd number of 1 in each byte.");
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

        private static long Encode(long[] roundKeys, long plaintext)
        {
            int[] initialPermutationTable = DesTables.IP;
            long initiallyPermuted = Bits.Permute(plaintext, 64, initialPermutationTable);
            long left = Bits.Subrange(initiallyPermuted, 32, 32);
            long right = Bits.Subrange(initiallyPermuted, 0, 32);

            for (int i = 0; i < 16; i++)
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

            int[][] substitutionBoxes = DesTables.S;

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
                    return (long)substitutionBoxes[i][coord];
                })
                .Reverse();
            for (int i = 0; i < 8; i++)
            {
                var b = sixBitsBlocks.ElementAt(i);
                long row = Bits.Subrange(b, 5, 1) | Bits.Subrange(b, 0, 1);
                long col = Bits.Subrange(b, 1, 4);
                long coord = Bits.Join(row, col, 4);
            }
            var sBoxes = Bits.Join(fourBitBlocks, 4);

            int[] permutationTable = DesTables.P;
            long permutated32BitBlock = Bits.Permute(sBoxes, 32, permutationTable);
            return permutated32BitBlock;
        }
    }
}
