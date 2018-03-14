using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DTOperator
{
	class Logger
	{
		private DateTime logStamp;
		private FileStream fileLogger;
		private static Logger instance = null;
		private Queue<Log> queue = null;
		private AutoResetEvent wakeup;
		private Object qMutex = null;

		public static Logger GetInstance()
		{
			if(instance == null)
			{
				instance = new Logger();
			}
			return instance;
		}

		private Logger()
		{
			//won't know until later whether file logging or not.

			queue = new Queue<Log>();
			wakeup = new AutoResetEvent(false); //Q is empty at the beginning
            qMutex = new Object();

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

					//if doing file logging and the log is too old (or this is the 1st log), create a new file
					DateTime now = DateTime.Now;
					if (!Server.DBLogs && (fileLogger == null || ((now - logStamp).Days > 0)))
					{
						if (fileLogger != null)
						{
							fileLogger.Close();
						}
						logStamp = now;
						String nowString = now.ToString("MM_dd_yyyy_HH_mm") + ".log";

						try
						{
							fileLogger = new FileStream(Const.LOGFOLDER + nowString, FileMode.OpenOrCreate);
						}
						catch (Exception e)
						{
							Console.WriteLine("Couldn't create log file: " + e.Message + "\n" + e.StackTrace);
						}
					}

					//write the log to the appropriate place
					if (!Server.DBLogs && (fileLogger != null))
					{
						byte[] logbytes = log.ToBytes();
						fileLogger.Write(logbytes, 0, logbytes.Length);
						fileLogger.Flush();
					}
					if(Server.DBLogs)
					{
						DBUtils.GetInstnace().WriteDBLog(log);
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
