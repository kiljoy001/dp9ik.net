using FluentAssertions;
using Microsoft.Coyote.SystematicTesting;
using CoyoteTask = Microsoft.Coyote.Tasks.Task;

namespace Dp9ik.Tests;

public sealed class NativeConcurrencyCoyoteTests
{
    [Fact]
    public void Coyote_Concurrent_Native_Operations_Remain_Stable()
    {
        var configuration = Microsoft.Coyote.Configuration.Create()
            .WithTestingIterations(25)
            .WithMaxSchedulingSteps(200);

        var engine = TestingEngine.Create(configuration, async () =>
        {
            var tasks = Enumerable.Range(0, 3).Select(_ => CoyoteTask.Run(ExerciseNativeFlowAsync)).ToArray();
            await CoyoteTask.WhenAll(tasks);
        });

        engine.Run();
        engine.TestReport.NumOfFoundBugs.Should().Be(0, engine.TestReport.BugReports.FirstOrDefault()?.ToString() ?? "no bug report");
    }

    private static async CoyoteTask ExerciseNativeFlowAsync()
    {
        await CoyoteTask.Yield();

        var request = new TicketRequest(AuthMessageType.AuthPak);
        request.SetAuthId("scott");
        request.SetAuthDomain("example.test");
        request.SetChallenge("chal1234"u8);
        request.SetHostId("file-server");
        request.SetUserId("scott");

        var encoded = request.Marshal();

        TicketRequest.TryUnmarshal(encoded, out var decoded, out var consumed).Should().BeTrue();
        consumed.Should().Be(Dp9ikConstants.TicketRequestLength);
        decoded.Should().NotBeNull();
        decoded!.AuthDomainText.Should().Be("example.test");
    }
}
