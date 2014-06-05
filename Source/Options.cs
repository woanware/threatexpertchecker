using System;
using CommandLine;
using CommandLine.Text;

namespace threatexpertchecker
{
    /// <summary>
    /// Internal class used for the command line parsing
    /// </summary>
    internal class Options : CommandLineOptionsBase
    {
        [Option("f", "file", Required = false, DefaultValue = "", HelpText = "File containing hashes")]
        public string File { get; set; }

        [Option("h", "hash", Required = false, DefaultValue = "", HelpText = "A single hash")]
        public string Hash { get; set; }

        [Option("d", "delimiter", Required = false, DefaultValue = ",", HelpText = "The delimiter used for the export. Defaults to \",\"")]
        public string Delimiter { get; set; }

        [Option("o", "output", Required = false, DefaultValue = "", HelpText = @"Output directory (use ""."" for the current dir)")]
        public string Output { get; set; }

        [Option("b", "database", Required = false, DefaultValue = "", HelpText = @"Path to directory containing database (te.db)")]
        public string Database { get; set; }

        [Option("m", "mode", Required = true, DefaultValue = "c", HelpText = @"Mode e.g. c = caching, d = database only, l = live")]
        public string Mode { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            var help = new HelpText
            {
                Copyright = new CopyrightInfo("woanware", 2013),
                AdditionalNewLineAfterOption = false,
                AddDashesToOption = true
            };

            this.HandleParsingErrorsInHelp(help);

            help.AddPreOptionsLine("Usage: threatexpertchecker -t hash -h \"MD5\" -d \"\\t\" -o \"C:\\output.csv\"");
            help.AddPreOptionsLine("       threatexpertchecker -t file -f \"hashes.txt\"");
            help.AddOptions(this);

            return help;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="help"></param>
        private void HandleParsingErrorsInHelp(HelpText help)
        {
            if (this.LastPostParsingState.Errors.Count > 0)
            {
                var errors = help.RenderParsingErrorsText(this, 2); // indent with two spaces
                if (!string.IsNullOrEmpty(errors))
                {
                    help.AddPreOptionsLine(string.Concat(Environment.NewLine, "ERROR(S):"));
                    help.AddPreOptionsLine(errors);
                }
            }
        }
    }
}
