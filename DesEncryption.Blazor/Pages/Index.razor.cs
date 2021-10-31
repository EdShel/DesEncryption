using Microsoft.AspNetCore.Components;
using System.Text;
using System.Text.RegularExpressions;

// I apologize for this code, this is not how I usually write.
// Just had limited time.

namespace DesEncryption.Blazor.Pages
{
    public class EntropyData
    {
        public int Step { get; set; }
        public long Left { get; set; }
        public long Right { get; set; }
    }

    public partial class Index
    {
        private string inputText = "";
        private string inputHex = "";
        private string key = "";
        private string result = string.Empty;
        private DesKeyStrength keyStrength = DesKeyStrength.Invalid;

        private bool canDoOperation = false;

        private string error = string.Empty;

        private List<EntropyData> entropyData = new List<EntropyData>();

        private void Encrypt()
        {
            var bytes = HexToBytes(inputHex).Reverse().ToArray();
            var data = BitConverter.ToInt64(bytes);
            var key = Convert.ToInt64(this.key, 16);
            try
            {
                entropyData.Clear();
                var encryptResult = Des.Encrypt(key, data, (step, left, right) => entropyData.Add(new EntropyData
                {
                    Step = step,
                    Left = left,
                    Right = right
                }));
                this.result = Convert.ToString(encryptResult, 16);
                this.error = String.Empty;
            }
            catch (Exception ex)
            {
                this.error = ex.Message;
            }
        }
        private void Decrypt()
        {
            var bytes = HexToBytes(inputHex).Reverse().ToArray();
            var data = BitConverter.ToInt64(bytes);
            var key = Convert.ToInt64(this.key, 16);
            try
            {
                var decryptResult = Des.Decrypt(key, data);
                this.result = Convert.ToString(decryptResult, 16);
                this.error = String.Empty;
            }
            catch (Exception ex)
            {
                this.error = ex.Message;
            }
        }

        private void OnFixKey()
        {
            try
            {
                var key = Convert.ToInt64(this.key, 16);
                var bytes = BitConverter.GetBytes(key);
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = Bits.CountOfOnes(bytes[i]).IsOdd()
                        ? bytes[i]
                        : (byte)(bytes[i] ^ 0x80);
                }
                this.key = Convert.ToString(BitConverter.ToInt64(bytes, 0), 16);
                ValidateForm();
                UpdateKeyStrength();
            }
            catch { }
        }

        void OnPlaintextChange(ChangeEventArgs e)
        {
            string newInputText = e.Value as string ?? string.Empty;
            this.inputText = newInputText;
            this.inputHex = Convert.ToString(
                BitConverter.ToInt64(
                    Encoding.ASCII.GetBytes(this.inputText.PadRight(8, '\0'))
                        .Reverse()
                        .ToArray()
                    ),
                16);
            ValidateForm();
        }

        void OnPlaintextHexChange(ChangeEventArgs e)
        {
            string textHex = e.Value as string ?? string.Empty;
            var hexValidated = new Regex(@"[^0-9a-fA-F]").Replace(textHex, string.Empty).PadLeft(16, '0');
            this.inputText = Encoding.ASCII.GetString(HexToBytes(hexValidated));
            this.inputHex = hexValidated;
            ValidateForm();
        }

        void OnKeyChange(ChangeEventArgs e)
        {
            string newKey = e.Value as string ?? string.Empty;
            this.key = new Regex(@"[^0-9a-fA-F]").Replace(newKey, string.Empty);
            ValidateForm();
            UpdateKeyStrength();
        }

        void ValidateForm()
        {
            this.canDoOperation = this.inputText.Length == 8
                && this.key.Length == 16;
            this.error = string.Empty;
        }

        public static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        string HexToText(string text)
        {
            return Encoding.ASCII.GetString(HexToBytes(text.PadLeft(16, '0')));
        }

        void UpdateKeyStrength()
        {
            try
            {
                this.keyStrength = Des.GetKeyStrength(Convert.ToInt64(this.key, 16));
            }
            catch (Exception)
            {
                this.keyStrength = DesKeyStrength.Invalid;
            }
        }
    }
}
