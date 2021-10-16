namespace DesEncryption
{
    public static class Numbers
    {
        public static bool IsOdd(this int number)
        {
            return (number & 1) == 1;
        }
    }
}
