using System.Diagnostics;

namespace Dp9ik.Tests.Support;

/// <summary>
/// The drawterm-derived dp9ik_native_tool, used only by tests as an independent reference for
/// the managed implementation. Secrets on its command line are acceptable here, never in the library.
/// </summary>
internal static class ReferenceTool
{
    private static readonly string ToolPath = Path.Combine(AppContext.BaseDirectory, "dp9ik_native_tool");

    internal static string[] Run(params string[] arguments) => Execute(out _, arguments);

    internal static int ExitCode(params string[] arguments)
    {
        Execute(out int code, arguments, throwOnFailure: false);
        return code;
    }

    private static string[] Execute(out int exitCode, string[] arguments, bool throwOnFailure = true)
    {
        var start = new ProcessStartInfo(ToolPath) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start) ?? throw new InvalidOperationException("Could not start dp9ik_native_tool.");
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        exitCode = process.ExitCode;
        if (throwOnFailure && exitCode != 0)
        {
            throw new InvalidOperationException($"dp9ik_native_tool {arguments[0]} failed with {exitCode}: {error}");
        }

        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
