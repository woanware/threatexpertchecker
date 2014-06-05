
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using woanware;

namespace threatexpertchecker
{
    public class Checker
    {
        public event threatexpertchecker.Global.HashCheckedEvent HashChecked;
        public event woanware.Events.MessageEvent Complete;
        public event woanware.Events.DefaultEvent Cancelled;
        public event woanware.Events.MessageEvent Error;
        public event woanware.Events.MessageEvent Update;

        #region Member Variables
        public bool IsRunning { get; private set; }
        private string _databasePath;
        private readonly object _lock = new object();
        private bool _stop;
        private int _scanDaysThreshold = 30;
        private List<string> _tempHashes;
        private static AutoResetEvent _done = null;
        private string _proxy = string.Empty;
        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <param name="databasePath"></param>
        public Checker(string databasePath, string proxy)
        {
            _databasePath = databasePath;
            _proxy = proxy;

            if (File.Exists(Db.GetDbPath(databasePath)) == false)
            {
                string db = Db.CreateDatabase(databasePath);
                if (db.Length > 0)
                {
                    OnError("An error occurred whilst creating the database: " + db);

                    db = IO.DeleteFile(Db.GetDbPath(databasePath));
                    if (db.Length > 0)
                    {
                        OnError("Unable to delete the database, delete it manually: " + Db.GetDbPath(databasePath));
                        return;
                    }
                }
            }
        }

        #region Public Methods
        /// <summary>
        /// 
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="live"></param>
        public void Start(string hash,
                          Global.Mode mode)
        {
            lock (_lock)
            {
                if (IsRunning == true)
                {
                    OnError("Cache checker is already running");
                    return;
                }

                _stop = false;
                IsRunning = true;
            }

            Process(hash, mode);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="file"></param>
        /// <param name="mode"></param>
        public void StartFile(string file,
                              Global.Mode mode)
        {
            lock (_lock)
            {
                if (IsRunning == true)
                {
                    OnError("Checker is already running");
                    return;
                }

                _stop = false;
                IsRunning = true;
            }

            ProcessFile(file, mode);
        }

        /// <summary>
        /// 
        /// </summary>
        public void Stop()
        {
            _stop = true;
        }
        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="mode"></param>
        private void Process(string hash,
                             Global.Mode mode)
        {
            (new Thread(() =>
            {
                try
                {
                    DateTime start = DateTime.Now;

                    using (DbConnection dbConnection = Db.GetOpenConnection(_databasePath))
                    using (var db = new NPoco.Database(dbConnection, NPoco.DatabaseType.SQLCe))
                    {
                        hash = hash.Trim();
                        if (hash.Length == 0)
                        {
                            return;
                        }

                        Hash temp = null;
                        if (mode != Global.Mode.Live)
                        {
                            temp = IsHashInDatabase(db, hash);
                        }

                        if (temp == null)
                        {
                            if (mode == Global.Mode.Cache |
                                mode == Global.Mode.Live)
                            {
                                CheckHash(db, hash);
                            }
                            else
                            {
                                // The hash wasn't in VT
                                temp = new Hash();
                                temp.Md5 = hash;
                                temp.Info = string.Empty;
                                OnHashChecked(temp);
                            }
                        }
                        else
                        {
                            OnHashChecked(temp);
                        }
                    }

                    DateTime end = DateTime.Now;
                    OnComplete((end - start).ToString());
                }
                catch (Exception ex)
                {
                    OnError(ex.ToString());
                }
            })).Start();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="live"></param>
        private void ProcessFile(string fileName,
                                 Global.Mode mode)
        {
            (new Thread(() =>
            {
                try
                {
                    DateTime start = DateTime.Now;

                    using (DbConnection dbConnection = Db.GetOpenConnection(_databasePath))
                    using (var db = new NPoco.Database(dbConnection, NPoco.DatabaseType.SQLCe))
                    using (System.IO.StreamReader file = new System.IO.StreamReader(fileName))
                    {
                        string line = string.Empty;
                        while ((line = file.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (line.Length == 0)
                            {
                                break;
                            }

                            if (_stop == true)
                            {
                                OnCancelled();
                                return;
                            }

                            Hash hash = IsHashInDatabase(db, line);
                            if (hash == null)
                            {
                                CheckHash(db, line);
                            }
                            else
                            {
                                OnHashChecked(hash);
                            }
                        }
                    }

                    DateTime end = DateTime.Now;
                    OnComplete((end - start).ToString());
                }
                catch (Exception ex)
                {
                    OnError(ex.ToString());
                }
            })).Start();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="db"></param>
        /// <param name="virusTotal"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        private Hash IsHashInDatabase(NPoco.Database db,
                                      string hash)
        {
            try
            {
                string sql = "WHERE Md5 = @0";

                var ret = db.SingleOrDefault<Hash>(sql, hash);
                if (ret == null)
                {
                    return null;
                }
                else
                {
                    if (ret.UpdateDate.AddDays(_scanDaysThreshold) > DateTime.Now)
                    {
                        return ret;
                    }

                    // The scan threshold has passed so say we haven't identified in DB
                    return null;
                }
            }
            catch (Exception ex)
            {
                OnError(ex.ToString());
                return null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="db"></param>
        /// <param name="hash"></param>
        private void CheckHash(NPoco.Database db, 
                               string hash)
        {
            string url = "http://www.threatexpert.com/report.aspx?md5=" + hash;

            try
            {
                GZipWebClient wc = new GZipWebClient();

                if (_proxy.Length == 0)
                {
                    wc.Proxy = System.Net.HttpWebRequest.GetSystemWebProxy();
                }
                else
                {
                    wc.Proxy = new WebProxy(_proxy);
                }

                WebClientResult wcr = wc.Download(url, 1);

                Regex regex = new Regex(@"<title>ThreatExpert Report:\s+(.*)</title>", RegexOptions.IgnoreCase);
                Match match = regex.Match(wcr.Response);
                if (match.Success == true)
                {
                    Hash temp = new Hash();
                    temp.Md5 = hash;
                    temp.Info = match.Groups[1].Value;
                    temp.UpdateDate = DateTime.Now;
                    UpdateDatabase(db, temp);
                    OnHashChecked(temp);
                }
                else
                {
                    Hash temp = new Hash();
                    temp.Md5 = hash;
                    temp.Info = "Not Found";
                    temp.UpdateDate = DateTime.Now;
                    OnHashChecked(temp);
                    return;
                }
            }
            catch (Exception ex)
            {
                OnError(ex.ToString());
            }
            finally
            {
                Thread.Sleep(new TimeSpan(0, 0, 1));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="db"></param>
        /// <param name="hash"></param>
        private void UpdateDatabase(NPoco.Database db, Hash hash)
        {
            try
            {
                var ret = db.SingleOrDefault<Hash>("WHERE Md5 = @0", hash.Md5);
                if (ret == null)
                {
                    db.Insert(hash);
                }
                else
                {
                    ret.UpdateDate = DateTime.Now;
                    db.Update(ret);
                }
            }
            catch (Exception ex)
            {
                OnError(ex.ToString());
            }
        }

        #region Event Handler Methods
        /// <summary>
        /// 
        /// </summary>
        /// <param name="hash"></param>
        private void OnHashChecked(Hash hash)
        {
            var handler = HashChecked;
            if (handler != null)
            {
                handler(hash);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        private void OnComplete(string duration)
        {
            var handler = Complete;
            if (handler != null)
            {
                handler(duration);
            }

            lock (_lock)
            {
                IsRunning = false;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        private void OnCancelled()
        {
            var handler = Cancelled;
            if (handler != null)
            {
                handler();
            }

            lock (_lock)
            {
                IsRunning = false;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        private void OnError(string message)
        {
            var handler = Error;
            if (handler != null)
            {
                handler(message);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        private void OnUpdate(string message)
        {
            var handler = Update;
            if (handler != null)
            {
                handler(message);
            }
        }
        #endregion
    }
}
