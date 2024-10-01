using System.CommandLine;
using System.Threading.Tasks;

namespace ImpTgsReq
{
  class Program
  {
    static async Task<int> Main(string[] args)
    {
      // defining options
      var sessionLuidOption = new Option<uint>(
          name: "--session-luid",
          description: "The LUID of a session to impersonate while requesting an ST");
      sessionLuidOption.AddAlias("-l");
      var targetServiceSpnOption = new Option<string>(
          name: "--spn",
          description: "TGS sname property value (target service's SPN)");
      targetServiceSpnOption.AddAlias("-s");

      // defining commands
      var rootCommand = new RootCommand("Invoke an impersonative TGS-REQ");
      var enumerateLogonSessionsCommand = 
        new Command(
            "enum-logon",
            "List local logon sessions' LUIDs. Administrative privileges are required for querying other accounts' sessions."){};

      // adding options and commands
      rootCommand.Add(sessionLuidOption);
      rootCommand.Add(targetServiceSpnOption);
      rootCommand.Add(enumerateLogonSessionsCommand);

      // settings handlers
      enumerateLogonSessionsCommand.SetHandler((boolean) =>
          {
          Secondary.EnumerateLogonSessions(true);
          });

      rootCommand.SetHandler((requestorPrincipalOptionValue, targetServiceSpnOptionValue) => 
          {Secondary.ImpTgsReq(requestorPrincipalOptionValue, targetServiceSpnOptionValue);}, 
          sessionLuidOption, targetServiceSpnOption);

      return await rootCommand.InvokeAsync(args);
    }
  }
}
