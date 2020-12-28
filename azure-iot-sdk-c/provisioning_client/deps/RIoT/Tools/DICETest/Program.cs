/*
 * Microsoft Copyright, 2017
 * Author: pengland
 */
using System;
using System.Threading;
using System.IO;
using System.Diagnostics;

namespace DICETest
{
    /// <summary>
    /// This command line program performs certificate validation for DICE certificate chains.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            // Usage:
            // -option c0 c1 c2...
            if (args.Length == 0 || args[1] == "?")
            {
                PrintHelp();
                return;
            }

            if (args[0] == "-chain")
            {
                if (args.Length < 2)
                {
                    ParmCountError("At least two certs in chain");
                    return;
                }

                var certs = GetCertNames(args, 1);
                if (certs == null) { Finish(); return; }
                CertChecker c = new CertChecker();
                bool ok = c.SetCerts(certs);
                if (!ok) { Finish(); return; };
                ok = c.CheckChain();

                if (!ok)
                {
                    Program.Print("One or more errors in certificate chain.", NotifyType.Error);
                }
                {
                    Program.Print("Certificates and certificate chain are valid.", NotifyType.Success);
                }
                Finish();
                return;
            }

            if (args[0] == "-pop")
            {
                if (args.Length != 4)
                {
                    ParmCountError("challenge and cert needed");
                    return;
                }
                var certs = GetCertNames(args, 2);
                if (certs == null) { Finish(); return; }
                CertChecker c = new CertChecker();
                bool ok = c.SetCerts(certs);
                if (!ok) { Finish(); return; };

                string challengeCn = args[1];
                ok = c.CheckPopCert(challengeCn);

                if (!ok)
                {
                    Program.Print("One or more errors in PoP cert.", NotifyType.Error);
                }
                else
                {
                    Program.Print("PoP cert is good", NotifyType.Success);
                }
                Finish();
                return;
            }

            if (args[0] == "-csr")
            {
                if (args.Length != 2)
                {
                    ParmCountError("Just CSR.PEM needed");
                    return;
                }
                bool ok = CertChecker.CheckCSR(args[1]);

                if (!ok)
                {
                    Program.Print("One or more errors in CSR.", NotifyType.Error);
                }
                {
                    Program.Print("CSR is well formed.", NotifyType.Success);
                }
                Finish();
                return;
            }

            Program.Print($"Option not recognized: {args[0]}", NotifyType.Error);
            PrintHelp();
            Finish();
        }


        /// <summary>
        /// Helper message writer for argument errors
        /// </summary>
        /// <param name="message"></param>
        static void ParmCountError(string message)
        {
            Program.Print($"Wrong number of parameters: {message}", NotifyType.Error);
            PrintHelp();
            Finish();
            return;
        }

        /// <summary>
        /// Print the help and usage message
        /// </summary>
        static void PrintHelp()
        {
            string eol = "\r\n";
            String nm = System.IO.Path.GetFileName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            String s = $"Validates DICE certificates and certificate chains.  Usage:{eol}" +
                $"{nm} -chain AliasCert.PEM DeviceIDCert.PEM ...  Root.PEM  - Checks the alias, deviceID, and vendor cert chain (DevID may be self-signed){eol}" +
                $"{nm} -csr CSR.PEM                                         - Checks a CSR (certificate signing request){eol}" +
                $"{nm} -pop SubjectName RootPOP.PEM                         - Checks a proof-of-possession cert{eol}";
            Print(s, NotifyType.Error);
            return;
        }

        /// <summary>
        /// Print helper with color highlighing
        /// </summary>
        /// <param name="s"></param>
        /// <param name="tp"></param>
        internal static void Print(string s, NotifyType tp)
        {
            switch(tp)
            {
                case NotifyType.Error: Console.ForegroundColor = ConsoleColor.Red; break;
                case NotifyType.Warning: Console.ForegroundColor = ConsoleColor.Yellow; break;
                case NotifyType.Success: Console.ForegroundColor = ConsoleColor.Green; break;
                case NotifyType.Notify: Console.ResetColor(); break;
            }
            Debug.WriteLine(s);
            Console.WriteLine(s);
            Console.ResetColor();
            return;
        }

        /// <summary>
        /// Get file names from the command line parameters, and check that the files exist.
        /// </summary>
        /// <param name="args">Args parameter passed to main()</param>
        /// <param name="startAt">Optionally skip one or more parms</param>
        /// <returns>Array of cert file names</returns>
        static string[] GetCertNames(string[] args, int startAt)
        {
            int numCerts = args.Length - startAt;
            string[] certNames = new string[numCerts];
            bool ok = true;
            for (int j = 0; j < numCerts;j++)
            {
                string fileName = args[j+startAt];
                if(!File.Exists(fileName))
                {
                    Print($"File not found: {args[j+startAt]}", NotifyType.Error);
                    ok = false;
                } else
                {
                    certNames[j] = fileName;
                }
            }
            if (!ok) return null;
            return certNames;
        }

        /// <summary>
        /// Clean up prior to exit
        /// </summary>
        static void Finish()
        {
            if (Debugger.IsAttached)
            {
                Thread.Sleep(3000);
            }
        }
    }
    /// <summary>
    /// Type of message
    /// </summary>
    internal enum NotifyType
    {
        Error,
        Warning,
        Success, 
        Notify
    }

}
