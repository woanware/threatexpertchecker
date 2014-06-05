using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;
using woanware;

namespace threatexpertchecker
{
    class Program
    {
        #region Member Variables
        private static ManualResetEvent _reset;
        private static Options _options;
        private static long _countTotal = 0;
        private static long _countIdentified = 0;
        private static Settings _settings;
        #endregion

        static void Main(string[] args)
        {
            try
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
                AssemblyName assemblyName = assembly.GetName();

                Console.WriteLine(Environment.NewLine + "threatexpertchecker v" + assemblyName.Version.ToString(3) + Environment.NewLine);

                _options = new Options();
                if (CommandLineParser.Default.ParseArguments(args, _options) == false)
                {
                    return;
                }

                string databasePath = string.Empty;
                if (_options.Database.Length > 0)
                {
                    databasePath = _options.Database;
                }
                else
                {
                    databasePath = Misc.GetApplicationDirectory();
                }

                _settings = new Settings();
                string ret = _settings.Load();
                if (ret.Length > 0)
                {
                    Console.WriteLine(ret);
                    return;
                }

                Global.Mode mode = Global.Mode.Cache;
                switch (_options.Mode.ToLower())
                {
                    case "c":
                        mode = Global.Mode.Cache;
                        break;
                    case "d":
                        mode = Global.Mode.Database;
                        break;
                    case "l":
                        mode = Global.Mode.Live;
                        break;
                    default:
                        Console.WriteLine("Invalid mode e.g. c = caching, d = database only, l = live");
                        return;
                }

                if (_options.File.Length == 0 & _options.Hash.Length == 0)
                {
                    Console.WriteLine("Either the file or hash parameter must be set");
                    return;
                }

                if (_options.File.Length > 0 & _options.Hash.Length > 0)
                {
                    Console.WriteLine("Both the file and hash parameters have been set. Choose one or the other");
                    return;
                }

                if (_options.File.Trim().Length > 0)
                {
                    if (_options.Output.Length == 0)
                    {
                        Console.WriteLine("The output parameter must be set");
                        return;
                    }

                    if (File.Exists(_options.File) == false)
                    {
                        Console.WriteLine("The input file does not exist");
                        return;
                    }
                }

                Checker checker = new Checker(databasePath, _settings.Proxy);
                checker.HashChecked += OnCacheChecker_HashChecked;
                checker.Complete += OnCacheChecker_Complete;
                checker.Error += OnCacheChecker_Error;

                // Output the CSV file header
                IO.WriteTextToFile(string.Format("{1}{0}{2}" + Environment.NewLine, GetDelimiter(), "MD5", "INFO"), System.IO.Path.Combine(_options.Output, "threatexpertchecker.csv"), false);

                if (_options.File.Length > 0)
                {
                    checker.StartFile(_options.File, mode);
                }
                else
                {
                    checker.Start(_options.Hash, mode);
                }

                _reset = new ManualResetEvent(false);
                _reset.WaitOne();
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }

        #region Cache Checker Event Handlers
        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        private static void OnCacheChecker_Error(string message)
        {
            if (System.IO.Directory.Exists(Misc.GetUserDataDirectory()) == false)
            {
                System.IO.Directory.CreateDirectory(Misc.GetUserDataDirectory());
            }

            IO.WriteTextToFile(DateTime.Now.ToString("s") + ":" + message + Environment.NewLine, System.IO.Path.Combine(Misc.GetUserDataDirectory(), "Errors.txt"), true);

            Console.WriteLine(message);
        }

        /// <summary>
        /// 
        /// </summary>
        private static void OnCacheChecker_Complete(string message)
        {
            Console.WriteLine(string.Empty);
            Console.WriteLine("No. of checked hashes: " + _countTotal);
            Console.WriteLine("No. of positive hashes: " + _countIdentified);
            Console.WriteLine("Duration: " + message);
            Console.WriteLine("Complete");
            _reset.Set();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hash"></param>
        private static void OnCacheChecker_HashChecked(Hash hash)
        {
            _countTotal++;

            if (hash.Info != "Not Found")
            {
                _countIdentified++;
            }

            Console.WriteLine(hash.Md5 + ": " + hash.Info);

            if (_options.Output.Length > 0)
            {
                IO.WriteTextToFile(string.Format("{1}{0}{2}" + Environment.NewLine, GetDelimiter(), hash.Md5, hash.Info), System.IO.Path.Combine(_options.Output, "threatexpertchecker.csv"), true);
            }
        }
        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private static char GetDelimiter()
        {
            switch (_options.Delimiter)
            {
                case "'\\t'":
                    return '\t';
                case "\\t":
                    return '\t';
                default:
                    return char.Parse(_options.Delimiter);
            }
        }
    }
}
