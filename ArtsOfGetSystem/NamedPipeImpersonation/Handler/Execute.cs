using System;
using NamedPipeImpersonation.Library;

namespace NamedPipeImpersonation.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();
                return;
            }

            Console.WriteLine();

            do
            {
                try
                {
                    Globals.Timeout = Convert.ToInt32(options.GetValue("timeout"));
                }
                catch
                {
                    Console.WriteLine("[-] Failed to parse timeout. Use default value (3,000 ms).");
                    Globals.Timeout = 3000;
                }

                try
                {
                    var methodId = (uint)Convert.ToInt32(options.GetValue("method"));

                    if (methodId < 3)
                        Globals.MethodId = methodId;
                    else
                        throw new ArgumentException();
                }
                catch
                {
                    Console.WriteLine("[-] Failed to specify method, or invalid method ID.");
                    break;
                }

                Modules.GetSystemWithNamedPipe(options.GetValue("command"));
            } while (false);

            Console.WriteLine();
        }
    }
}
