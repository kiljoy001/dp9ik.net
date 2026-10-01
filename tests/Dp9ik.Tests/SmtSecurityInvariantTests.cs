using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Dp9ik.P9Auth;
using FluentAssertions;

namespace Dp9ik.Tests;

public sealed class SmtSecurityInvariantTests
{
    [Fact]
    public void Known_Ticket_Type_Guard_Allows_Only_Expected_Wire_Values()
    {
        var symbolicValues = EnumerateByteModels(
            "ticketType",
            "(or (= ticketType 64) (= ticketType 65) (= ticketType 68))");
        var concreteValues = EnumerateByteValues(value => AuthMessageClassifier.IsKnownTicketType((AuthMessageType)value));

        // FluentAssertions compares byte sequences by position, and z3 enumerates models in a
        // version-dependent order, so the sets are compared sorted.
        symbolicValues.Order().Should().Equal(concreteValues.Order());
        concreteValues.Order().Should().Equal(new[]
        {
            (byte)AuthMessageType.AuthTs,
            (byte)AuthMessageType.AuthTc,
            (byte)AuthMessageType.AuthTp
        });
    }

    [Fact]
    public void Known_Authenticator_Type_Guard_Allows_Only_Expected_Wire_Values()
    {
        var symbolicValues = EnumerateByteModels(
            "authenticatorType",
            "(or (= authenticatorType 66) (= authenticatorType 67))");
        var concreteValues = EnumerateByteValues(value => AuthMessageClassifier.IsKnownAuthenticatorType((AuthMessageType)value));

        symbolicValues.Order().Should().Equal(concreteValues.Order());
        concreteValues.Order().Should().Equal(new[]
        {
            (byte)AuthMessageType.AuthAs,
            (byte)AuthMessageType.AuthAc
        });
    }

    [Fact]
    public void Handshake_Proof_Policy_Has_A_Single_Accepting_Shape()
    {
        var symbolicAcceptedShapes = EnumerateAcceptedProofShapes();
        var concreteAcceptedShapes = EnumerateConcreteAcceptedProofShapes();

        symbolicAcceptedShapes.Should().BeEquivalentTo(concreteAcceptedShapes);
        concreteAcceptedShapes.Should().ContainSingle().Which.Should().Be(new ProofShape(
            (byte)AuthMessageType.AuthTs,
            (byte)AuthMessageType.AuthAc,
            TicketChallengeMatches: true,
            AuthenticatorChallengeMatches: true,
            HasAuthenticatedUser: true));
    }

    private static HashSet<byte> EnumerateByteModels(string symbolName, string predicate)
    {
        var blockedValues = new HashSet<byte>();
        var values = new HashSet<byte>();

        while (true)
        {
            var assertions = new List<string>
            {
                $"(declare-const {symbolName} Int)",
                InByteRange(symbolName),
                $"(assert {predicate})"
            };

            assertions.AddRange(blockedValues.Select(value => $"(assert (not (= {symbolName} {value})))"));
            var result = RunZ3Query(assertions, symbolName);
            if (result.Status == "unsat")
            {
                return values;
            }

            var value = byte.Parse(result.Values[symbolName], System.Globalization.CultureInfo.InvariantCulture);
            values.Add(value);
            blockedValues.Add(value);
        }
    }

    private static string InByteRange(string symbolName) => $"(assert (and (<= 0 {symbolName}) (<= {symbolName} 255)))";

    private static HashSet<ProofShape> EnumerateAcceptedProofShapes()
    {
        var blockedShapes = new HashSet<ProofShape>();
        var shapes = new HashSet<ProofShape>();

        while (true)
        {
            var assertions = new List<string>
            {
                "(declare-const ticketType Int)",
                "(declare-const authenticatorType Int)",
                "(declare-const ticketChallengeMatches Bool)",
                "(declare-const authenticatorChallengeMatches Bool)",
                "(declare-const hasAuthenticatedUser Bool)",
                InByteRange("ticketType"),
                InByteRange("authenticatorType"),
                "(assert (= ticketType 64))",
                "(assert (= authenticatorType 67))",
                "(assert ticketChallengeMatches)",
                "(assert authenticatorChallengeMatches)",
                "(assert hasAuthenticatedUser)"
            };

            assertions.AddRange(blockedShapes.Select(BuildBlockedShapeAssertion));
            var result = RunZ3Query(
                assertions,
                "ticketType",
                "authenticatorType",
                "ticketChallengeMatches",
                "authenticatorChallengeMatches",
                "hasAuthenticatedUser");
            if (result.Status == "unsat")
            {
                return shapes;
            }

            var shape = new ProofShape(
                byte.Parse(result.Values["ticketType"], System.Globalization.CultureInfo.InvariantCulture),
                byte.Parse(result.Values["authenticatorType"], System.Globalization.CultureInfo.InvariantCulture),
                bool.Parse(result.Values["ticketChallengeMatches"]),
                bool.Parse(result.Values["authenticatorChallengeMatches"]),
                bool.Parse(result.Values["hasAuthenticatedUser"]));
            shapes.Add(shape);
            blockedShapes.Add(shape);
        }
    }

    private static string BuildBlockedShapeAssertion(ProofShape shape) =>
        "(assert (not (and "
        + $"(= ticketType {shape.TicketType}) "
        + $"(= authenticatorType {shape.AuthenticatorType}) "
        + $"(= ticketChallengeMatches {shape.TicketChallengeMatches.ToString().ToLowerInvariant()}) "
        + $"(= authenticatorChallengeMatches {shape.AuthenticatorChallengeMatches.ToString().ToLowerInvariant()}) "
        + $"(= hasAuthenticatedUser {shape.HasAuthenticatedUser.ToString().ToLowerInvariant()}))))";

    private static HashSet<byte> EnumerateByteValues(Func<byte, bool> predicate) =>
        Enumerable.Range(0, byte.MaxValue + 1)
            .Select(value => (byte)value)
            .Where(predicate)
            .ToHashSet();

    private static HashSet<ProofShape> EnumerateConcreteAcceptedProofShapes()
    {
        var shapes = new HashSet<ProofShape>();
        foreach (var ticketType in Enumerable.Range(0, byte.MaxValue + 1).Select(value => (byte)value))
        {
            foreach (var authenticatorType in Enumerable.Range(0, byte.MaxValue + 1).Select(value => (byte)value))
            {
                foreach (var ticketChallengeMatches in BooleanValues)
                {
                    foreach (var authenticatorChallengeMatches in BooleanValues)
                    {
                        foreach (var hasAuthenticatedUser in BooleanValues)
                        {
                            if (P9AuthSecurityPolicy.CanAcceptProof(
                                (AuthMessageType)ticketType,
                                (AuthMessageType)authenticatorType,
                                ticketChallengeMatches,
                                authenticatorChallengeMatches,
                                hasAuthenticatedUser))
                            {
                                shapes.Add(new ProofShape(
                                    ticketType,
                                    authenticatorType,
                                    ticketChallengeMatches,
                                    authenticatorChallengeMatches,
                                    hasAuthenticatedUser));
                            }
                        }
                    }
                }
            }
        }

        return shapes;
    }

    private static Z3Result RunZ3Query(IEnumerable<string> assertions, params string[] symbols)
    {
        var startInfo = new ProcessStartInfo("z3")
        {
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add("-in");
        startInfo.ArgumentList.Add("-smt2");

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start z3.");
        var script = new StringBuilder()
            .AppendLine("(set-logic QF_LIA)")
            .AppendLine("(set-option :produce-models true)");

        foreach (var assertion in assertions)
        {
            script.AppendLine(assertion);
        }

        script.AppendLine("(check-sat)");
        foreach (var symbol in symbols)
        {
            script.AppendLine($"(get-value ({symbol}))");
        }

        process.StandardInput.Write(script.ToString());
        process.StandardInput.Close();

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
        {
            throw new InvalidOperationException("z3 returned no output.");
        }

        var status = lines[0];
        if (status == "unsat")
        {
            return new Z3Result(status, new Dictionary<string, string>(StringComparer.Ordinal));
        }

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"z3 failed with exit code {process.ExitCode}: {error}\nSCRIPT:\n{script}\nOUTPUT:\n{output}");
        }

        if (status != "sat")
        {
            throw new InvalidOperationException($"Unexpected z3 status '{status}'.");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in lines.Skip(1))
        {
            var match = ValuePattern.Match(line);
            if (!match.Success)
            {
                throw new InvalidOperationException($"Unable to parse z3 value line '{line}'.");
            }

            values.Add(match.Groups["name"].Value, match.Groups["value"].Value);
        }

        return new Z3Result(status, values);
    }

    private static readonly bool[] BooleanValues = [false, true];

    private static readonly Regex ValuePattern = new(
        @"^\(\((?<name>[^\s]+)\s+(?<value>[^\)]+)\)\)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly record struct ProofShape(
        byte TicketType,
        byte AuthenticatorType,
        bool TicketChallengeMatches,
        bool AuthenticatorChallengeMatches,
        bool HasAuthenticatedUser);

    private sealed record Z3Result(string Status, IReadOnlyDictionary<string, string> Values);
}
