using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.Collections;

namespace DTOperator
{
    class DBUtils
    {
        private static DBUtils instance = null;

        private SqlConnection conn = null;
		private object sqllock = new object();

        public static DBUtils GetInstnace()
        {
            if(instance == null)
            {
                instance = new DBUtils();
            }
            return instance;
        }

        private DBUtils()
        {
            conn = new SqlConnection("Server=127.0.0.1;Database=dtoperator_windows;Integrated Security=SSPI");
			conn.Open();
        }

		//check if an account is enabled
        public bool IsEnabled(String username)
        {
            if(username == null || username.Equals(""))
            {
                Console.WriteLine("is enabled on null or empty user name?");
                return false;
            }

			lock (sqllock)
			{
				using (SqlCommand checkEnabled = new SqlCommand())
				{
					checkEnabled.CommandText = "select Enabled from Users where Username=@uname";
					checkEnabled.Parameters.AddWithValue("@uname", username);
					checkEnabled.CommandType = System.Data.CommandType.Text;
					checkEnabled.Connection = conn;

					try //public facing function that gets the user name. try/catch to prevent a malicious "user name" causing a fatal crash
					{
						using (SqlDataReader reader = checkEnabled.ExecuteReader())
						{
							if (reader.HasRows)
							{
								reader.Read();
								bool result = (bool)reader["enabled"];
								return result;
							}
							return false;
						}
					}
					catch (Exception e)
					{
						Logger.GetInstance().InsertLog(new Log(Log.TAG_DBUTILS, "user: " + username + "\n" + e.Message + "\n" + e.StackTrace, Log.SELF, Log.ERROR, Log.SELFIP));
						return false;
					}
				}
			}
        }

		//get a user's public key string dump
		public String GetDump(String username)
		{
			if (username == null || username.Equals(""))
			{
				Console.WriteLine("is enabled on null or empty user name?");
				return null;
			}

			lock (sqllock)
			{
				using (SqlCommand checkEnabled = new SqlCommand())
				{
					checkEnabled.CommandText = "select Keydump from Users where Username=@uname";
					checkEnabled.Parameters.AddWithValue("@uname", username);
					checkEnabled.CommandType = System.Data.CommandType.Text;
					checkEnabled.Connection = conn;

					using (SqlDataReader reader = checkEnabled.ExecuteReader())
					{
						if (reader.HasRows)
						{
							reader.Read();
							String result = (String)reader["Keydump"];
							return result;
						}
						return null;
					}
				}
			}
		}

		public void WriteDBLog(Log log)
		{
			if(log == null)
			{
				return;
			}

			lock (sqllock)
			{
				using (SqlCommand ins = new SqlCommand())
				{
					String command = "insert into logs (tag, message, [user], type, ip)" +
						"values (@tag, @msg, @user, @type, @ip)";
					ins.CommandText = command;
					ins.Parameters.AddWithValue("@tag", log.Tag);
					ins.Parameters.AddWithValue("@msg", log.Message);
					ins.Parameters.AddWithValue("@user", log.User);
					ins.Parameters.AddWithValue("@type", log.Type);
					ins.Parameters.AddWithValue("@ip", log.Ip);
					ins.CommandType = System.Data.CommandType.Text;
					ins.Connection = conn;
					ins.ExecuteNonQuery();
				}
			}
		}
    }
}
