using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DTOperator
{
	class FileLogger
	{
		private DateTime logStamp;
		private FileStream logger;
		private static FileLogger instance = null;
		private Queue<Log> queue = null;
		private AutoResetEvent wakeup;
		private Object qMutex = new Object();

		public static FileLogger GetInstance()
		{
			if(instance == null)
			{
				instance = new FileLogger();
			}
			return instance;
		}

		private FileLogger()
		{
			logStamp = DateTime.Now;
			String nowString = logStamp.ToString("MM_dd_yyyy_HH_mm") + ".log"; //windows version uses file extensions
			try
			{
				logger = new FileStream(Const.LOGFOLDER + nowString, FileMode.OpenOrCreate);
			}
			catch (Exception e)
			{
				Console.WriteLine("Couldn't create log file: " + e.Message + "\n" + e.StackTrace);
			}

			queue = new Queue<Log>();
			wakeup = new AutoResetEvent(false); //Q is empty at the beginning

			Thread diskRWThread = new Thread(() => DiskRW());
			try
			{
				diskRWThread.Name = "DiskRW";
				diskRWThread.Start();
			}
			catch(Exception e)
			{
				Console.WriteLine("Can't start disk rw thread in file logger");
				Console.WriteLine(e.Message);
			}
		}

		public void InsertLog(Log log)
		{
			lock (qMutex)
			{
				queue.Enqueue(log);
			}
			wakeup.Set();
		}

		private void DiskRW()
		{
			while (true)
			{
				bool empty;
				lock(qMutex)
				{
					empty = queue.Count() == 0;
				}

				while (!empty)
				{
					Log log;
					lock (qMutex)
					{
						log = queue.Dequeue();
						empty = queue.Count() == 0;
					}

					DateTime now = DateTime.Now;
					if ((now - logStamp).Days > 0)
					{
						if (logger != null)
						{
							logger.Close();
						}
						logStamp = now;
						String nowString = now.ToString("MM_dd_yyyy_HH_mm") + ".log";

						try
						{
							logger = new FileStream(Const.LOGFOLDER + nowString, FileMode.OpenOrCreate);
						}
						catch (Exception e)
						{
							Console.WriteLine("Couldn't create log file: " + e.Message + "\n" + e.StackTrace);
						}
					}

					if (logger != null)
					{
						byte[] logbytes = log.ToBytes();
						logger.Write(logbytes, 0, logbytes.Length);
						logger.Flush();
					}
					Console.WriteLine(log);
				}

				while(queue.Count() == 0)
				{
					wakeup.WaitOne();
				}
			}
		}
	}
}
