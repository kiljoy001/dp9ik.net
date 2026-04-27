using System.Diagnostics;

namespace Dp9ik;

internal static class NativeTool
{
    private static readonly string ToolPath = ResolveToolPath();

    internal static string[] Execute(params string[] arguments)
    {
        using var process = Start(arguments);
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"dp9ik_native_tool failed with exit code {process.ExitCode}: {error}");
        }

        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static Process Start(IEnumerable<string> arguments)
    {
        return Process.Start(CreateStartInfo(arguments)) ?? throw new InvalidOperationException("Failed to start dp9ik_native_tool.");
    }

    private static ProcessStartInfo CreateStartInfo(IEnumerable<string> arguments)
    {
        var startInfo = new ProcessStartInfo(ToolPath)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private static string ResolveToolPath()
    {
        var candidate = Path.Combine(AppContext.BaseDirectory, "dp9ik_native_tool");
        if (File.Exists(candidate))
        {
            return candidate;
        }

        throw new FileNotFoundException("Could not locate dp9ik_native_tool.");
    }
}
