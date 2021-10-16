namespace DesEncryption
{
    public static class Bits
    {
        public static int CountOfOnes(byte bits)
        {
            long sum = 0;
            for (int i = 0; i < 8; i++)
            {
                sum += (bits >> i) & 1;
            }
            return (int)sum;
        }

        public static long Permute(
            long bits,
            int bitsCount,
            int[] permutationTable) // Permutation table is bits order left to right
        {
            long permutedNumber = 0;
            for (int i = 0; i < permutationTable.Length; i++)
            {
                long bitValueAccordingToTable = (bits >> (bitsCount - permutationTable[i])) & 1;
                permutedNumber |= bitValueAccordingToTable << (permutationTable.Length - 1 - i);
            }
            return permutedNumber;
        }

        public static long Subrange(long bits, int start, int count)
        {
            return (bits >> start) & ((1L << count) - 1L);
        }

        public static long CyclicShiftLeft(long bits, int countOfBits, int shiftLength)
        {
            long shiftOverflow = Bits.Subrange(bits, countOfBits - shiftLength, countOfBits);
            return (shiftOverflow | (bits << shiftLength)) & ((1 << countOfBits) - 1);
        }

        public static long Join(
            long bigPart,
            long littlePart,
            int littlePartSize)
        {
            return (bigPart << littlePartSize) | littlePart;
        }

        public static long Join(IEnumerable<long> bitsPartsLittleToBig, int bitsInPart)
        {
            long result = 0;
            int totalSize = 0;
            foreach (var nextBigPart in bitsPartsLittleToBig)
            {
                result = Bits.Join(nextBigPart, result, totalSize);
                totalSize += bitsInPart;
            }
            return result;
        }
    }
}
