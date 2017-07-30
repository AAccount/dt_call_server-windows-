using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DTOperator
{
    class Utils
    {
        private static RandomNumberGenerator srand = RNGCryptoServiceProvider.Create();

        public static String Trim(String str)
        {
            if(str.Length == 0)
            {
                return str;
            }

			int comment = str.IndexOf("#");
			if (comment != -1)
			{
				str = str.Substring(0, comment);
			}

			str = str.Replace("\r\n\t", "");
            str = str.Trim();
			return str;
        }

		public static String RandomString(int length)
		{
			String[] chars = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
			"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
			"o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
			"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
			"O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};

			String result = "";
			int i=0;
			while(i < length)
			{
				byte[] indexByte = new byte[1];
				srand.GetBytes(indexByte);
				int index = (int)indexByte[0] % chars.Length;
				int multiples = Byte.MaxValue / chars.Length;
				if(index >= chars.Length*multiples)
				{//make it a secure UNIFORM distribution
					continue;
				}
				result = result + chars[index];
				i++;
			}
			return result;
		}
    }
}
