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
        private static RandomNumberGenerator srand = RandomNumberGenerator.Create();

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
			int multiples = Byte.MaxValue / chars.Length;
			int uniformDistMax = chars.Length * multiples;
			//Example: chars length is 10, Byte.MaxValue = 13
			//	then if index = (0-->13) % 10, 0,1,2,3 are more
			//	likely to be chosen compared to 4-->9 because
			//	0=0,10; 1=1,11; 2=2,12; 3=3,13; 4=4, 5=5, etc...
			//	If 10-->13 are chosen (in this example), redo the random pick

			String result = "";
			int i=0;
			while(i < length)
			{
				byte[] indexByte = new byte[1];
				srand.GetBytes(indexByte);
				int index = ((int)indexByte[0]) % chars.Length;
				if(index >= uniformDistMax)
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
