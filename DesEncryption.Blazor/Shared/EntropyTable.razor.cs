using DesEncryption.Blazor.Pages;
using Microsoft.AspNetCore.Components;

namespace DesEncryption.Blazor.Shared
{
    public partial class EntropyTable
    {
        [Parameter]
        public EntropyData EntropyData { get; set; }

        public IEnumerable<int> YieldBits(int byteIndex)
        {
            long combined = Bits.Join(EntropyData.Left, EntropyData.Right, 32);

            var thisByte = (combined >> ((7 - byteIndex) * 8)) & 0xFF;

            for (int i = 7; i >= 0; i--)
            {
                yield return (int)((thisByte >> i) & 1);
            }
        }

        public IEnumerable<float> YieldEntropyValues()
        {
            long combined = Bits.Join(EntropyData.Left, EntropyData.Right, 32);
            for (int bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                int countOfOnes = 0;
                int countOfZeroes = 0;
                for (int byteIndex = 0; byteIndex < 8; byteIndex++)
                {
                    long bit = (combined >> (byteIndex * 8 + bitIndex)) & 1;
                    if (bit == 1L)
                    {
                        countOfOnes++;
                    }
                    else
                    {
                        countOfZeroes++;
                    }
                }

                float zeroProbability = countOfZeroes / 8f;
                float oneProbability = countOfOnes / 8f;
                float entropy = -(MathF.Log2(zeroProbability) * zeroProbability + MathF.Log2(oneProbability) * oneProbability);

                yield return countOfOnes * countOfZeroes == 0 ? 0 : entropy;
            }
        }
    }
}
