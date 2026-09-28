using System.Collections.Concurrent;
using Appouse.Safetalk.Client.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Appouse.Safetalk.Client.Tests;

/// <summary>
/// <see cref="HmacSigningState"/> is shared by every attempt of one logical request (the message and its clones) and
/// must hand out strictly increasing, never repeated timestamps, even when attempts are signed concurrently.
/// </summary>
public sealed class HmacSigningStateTests
{
    private const long Now = 1_790_000_000;
    private const string StateKey = "Appouse.Safetalk.SigningState";

    [Fact]
    public void NextTimestamp_FirstCall_ReturnsTheClock()
    {
        var state = new HmacSigningState();

        Assert.Equal(Now, state.NextTimestamp(Now));
    }

    [Fact]
    public void NextTimestamp_SameSecond_ReturnsStrictlyIncreasingValues()
    {
        var state = new HmacSigningState();

        Assert.Equal([Now, Now + 1, Now + 2, Now + 3], new[] { state.NextTimestamp(Now), state.NextTimestamp(Now), state.NextTimestamp(Now), state.NextTimestamp(Now) });
    }

    [Fact]
    public void NextTimestamp_ClockAheadOfTheLastValue_FollowsTheClock()
    {
        var state = new HmacSigningState();
        state.NextTimestamp(Now);
        state.NextTimestamp(Now);

        Assert.Equal(Now + 60, state.NextTimestamp(Now + 60));
        Assert.Equal(Now + 61, state.NextTimestamp(Now + 60));
    }

    [Fact]
    public void NextTimestamp_ClockBehindTheLastValue_StillIncreases()
    {
        var state = new HmacSigningState();
        state.NextTimestamp(Now);

        Assert.Equal(Now + 1, state.NextTimestamp(Now - 3_600));
        Assert.Equal(Now + 2, state.NextTimestamp(Now - 1));
    }

    [Fact]
    public void NextTimestamp_ManyThreadsWithTheSameClock_ReturnUniqueContiguousStrictlyIncreasingValues()
    {
        const int threadCount = 16;
        const int callsPerThread = 5_000;
        var state = new HmacSigningState();

        long[][] results = RunConcurrently(threadCount, callsPerThread, (_, _) => Now, state);

        long[] all = [.. results.SelectMany(values => values)];
        Assert.Equal(threadCount * callsPerThread, all.Distinct().Count());
        Assert.Equal(Now, all.Min());
        Assert.Equal(Now + (threadCount * callsPerThread) - 1, all.Max());
        Assert.All(results, AssertStrictlyIncreasing);
        Assert.Equal(Now + (threadCount * callsPerThread), state.NextTimestamp(Now));
    }

    [Fact]
    public void NextTimestamp_ManyThreadsWithSkewedAndAdvancingClocks_ReturnUniqueValuesNeverBelowTheirClock()
    {
        const int threadCount = 12;
        const int callsPerThread = 4_000;
        var state = new HmacSigningState();

        // Every thread has its own view of "now": some lag behind, some run ahead, all advance at their own pace.
        static long ClockOf(int thread, int call) => Now + ((thread % 5) - 2) + (call / (50 + thread));

        long[][] results = RunConcurrently(threadCount, callsPerThread, ClockOf, state);

        long[] all = [.. results.SelectMany(values => values)];
        Assert.Equal(threadCount * callsPerThread, all.Distinct().Count());
        for (int thread = 0; thread < threadCount; thread++)
        {
            AssertStrictlyIncreasing(results[thread]);
            for (int call = 0; call < callsPerThread; call++)
            {
                Assert.True(results[thread][call] >= ClockOf(thread, call), $"Thread {thread}, call {call} went below its clock.");
            }
        }

        Assert.Equal(all.Max() + 1, state.NextTimestamp(Now - 2));
    }

    [Fact]
    public void GetOrAttach_NewRequest_AttachesAStateUnderTheSigningStateKey()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        HmacSigningState state = HmacSigningState.GetOrAttach(request);

        Assert.True(request.Options.TryGetValue(new HttpRequestOptionsKey<HmacSigningState>(StateKey), out HmacSigningState? stored));
        Assert.Same(state, stored);
        Assert.Single(request.Options);
    }

    [Fact]
    public void GetOrAttach_SameRequestTwice_ReturnsTheSameInstance()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        Assert.Same(HmacSigningState.GetOrAttach(request), HmacSigningState.GetOrAttach(request));
    }

    [Fact]
    public void GetOrAttach_CloneCopyingTheOptions_SharesTheStateAndContinuesTheSequence()
    {
        using var original = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");
        HmacSigningState state = HmacSigningState.GetOrAttach(original);
        Assert.Equal(Now, state.NextTimestamp(Now));

        using HttpRequestMessage clone = CloningHedgingHandler.Clone(original);

        Assert.Same(state, HmacSigningState.GetOrAttach(clone));
        Assert.Equal(Now + 1, HmacSigningState.GetOrAttach(clone).NextTimestamp(Now));
    }

    [Fact]
    public void GetOrAttach_DifferentRequests_GetIndependentStates()
    {
        using var first = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");
        using var second = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        HmacSigningState firstState = HmacSigningState.GetOrAttach(first);
        HmacSigningState secondState = HmacSigningState.GetOrAttach(second);

        Assert.NotSame(firstState, secondState);
        Assert.Equal(Now, firstState.NextTimestamp(Now));
        Assert.Equal(Now, secondState.NextTimestamp(Now));
    }

    [Fact]
    public void GetOrAttach_ForeignValueUnderTheKey_IsReplacedByAState()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");
        request.Options.Set(new HttpRequestOptionsKey<string>(StateKey), "not a state");

        HmacSigningState state = HmacSigningState.GetOrAttach(request);

        Assert.True(request.Options.TryGetValue(new HttpRequestOptionsKey<HmacSigningState>(StateKey), out HmacSigningState? stored));
        Assert.Same(state, stored);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StateHandler_Send_AttachesTheStateBeforeTheInnerHandlerRuns(bool synchronous)
    {
        var observed = new ConcurrentQueue<HmacSigningState?>();
        var probe = new OptionsProbeHandler(observed) { InnerHandler = new CapturingHandler() };
        using var handler = new HmacSigningStateHandler { InnerHandler = probe };
        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");

        using (synchronous
            ? invoker.Send(request, TestContext.Current.CancellationToken)
            : await invoker.SendAsync(request, TestContext.Current.CancellationToken))
        {
        }

        HmacSigningState? seen = Assert.Single(observed);
        Assert.NotNull(seen);
        Assert.Same(seen, HmacSigningState.GetOrAttach(request));
    }

    [Fact]
    public async Task StateHandler_RequestAlreadyCarryingAState_KeepsIt()
    {
        var observed = new ConcurrentQueue<HmacSigningState?>();
        using var handler = new HmacSigningStateHandler { InnerHandler = new OptionsProbeHandler(observed) { InnerHandler = new CapturingHandler() } };
        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");
        HmacSigningState existing = HmacSigningState.GetOrAttach(request);

        using (await invoker.SendAsync(request, TestContext.Current.CancellationToken))
        using (await invoker.SendAsync(request, TestContext.Current.CancellationToken))
        {
        }

        Assert.All(observed, seen => Assert.Same(existing, seen));
    }

    /// <summary>
    /// Clones of one request that share its state (as hedging clones do) and are signed at the same instant on many
    /// threads each get their own timestamp, so their signatures are all distinct and all verify.
    /// </summary>
    [Fact]
    public async Task SigningHandler_ClonesSharingOneStateSignedConcurrently_GetUniqueTimestampsAndVerifiableSignatures()
    {
        const int attempts = 64;
        var time = new FakeTimeProvider(SigningPipeline.StartTime);
        var transport = new CapturingHandler();
        using var signing = new HmacSigningHandler(
            new HmacClientOptions { ClientId = SigningPipeline.DefaultClientId, Secret = SigningPipeline.DefaultSecret },
            HmacSha256SignatureService.Instance,
            time,
            NullLogger<HmacSigningHandler>.Instance)
        {
            InnerHandler = transport,
        };
        using var invoker = new HttpMessageInvoker(signing, disposeHandler: false);
        using var original = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/orders?batch=7")
        {
            Content = new StringContent("{\"order\":7}"),
        };
        HmacSigningState.GetOrAttach(original);
        HttpRequestMessage[] clones = [.. Enumerable.Range(0, attempts).Select(_ => CloningHedgingHandler.Clone(original))];
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using var start = new ManualResetEventSlim();

        Task[] sends = [.. clones.Select(clone => Task.Run(
            async () =>
            {
                start.Wait(cancellationToken);
                using HttpResponseMessage response = await invoker.SendAsync(clone, cancellationToken);
            },
            cancellationToken))];
        start.Set();
        await Task.WhenAll(sends);

        IReadOnlyList<CapturedRequest> sent = transport.Requests;
        Assert.Equal(attempts, sent.Count);
        Assert.Equal(
            Enumerable.Range(0, attempts).Select(offset => (Now + offset).ToString(System.Globalization.CultureInfo.InvariantCulture)),
            sent.Select(r => r.Timestamp).Order(StringComparer.Ordinal));
        Assert.Equal(attempts, sent.Select(r => r.Signature).Distinct(StringComparer.Ordinal).Count());
        Assert.All(sent, attempt =>
        {
            Assert.Equal("{\"order\":7}"u8.ToArray(), attempt.Body);
            Assert.Equal(ReferenceSigner.Sign(SigningPipeline.DefaultSecret, attempt), attempt.Signature);
        });

        foreach (HttpRequestMessage clone in clones)
        {
            clone.Dispose();
        }
    }

    private static long[][] RunConcurrently(int threadCount, int callsPerThread, Func<int, int, long> clock, HmacSigningState state)
    {
        long[][] results = new long[threadCount][];
        using var barrier = new Barrier(threadCount);
        var failures = new ConcurrentQueue<Exception>();
        Thread[] threads = [.. Enumerable.Range(0, threadCount).Select(thread => new Thread(() =>
        {
            try
            {
                long[] values = new long[callsPerThread];
                barrier.SignalAndWait(TestContext.Current.CancellationToken);
                for (int call = 0; call < callsPerThread; call++)
                {
                    values[call] = state.NextTimestamp(clock(thread, call));
                }

                results[thread] = values;
            }
            catch (Exception exception)
            {
                failures.Enqueue(exception);
            }
        })
        {
            IsBackground = true,
        })];

        foreach (Thread thread in threads)
        {
            thread.Start();
        }

        foreach (Thread thread in threads)
        {
            Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "A worker thread did not finish in time.");
        }

        Assert.Empty(failures);
        return results;
    }

    private static void AssertStrictlyIncreasing(long[] values)
    {
        for (int i = 1; i < values.Length; i++)
        {
            Assert.True(values[i] > values[i - 1], $"Value {values[i]} at index {i} does not exceed {values[i - 1]}.");
        }
    }

    private sealed class OptionsProbeHandler(ConcurrentQueue<HmacSigningState?> observed) : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Record(request);
            return base.SendAsync(request, cancellationToken);
        }

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Record(request);
            return base.Send(request, cancellationToken);
        }

        private void Record(HttpRequestMessage request)
            => observed.Enqueue(request.Options.TryGetValue(new HttpRequestOptionsKey<HmacSigningState>(StateKey), out HmacSigningState? state) ? state : null);
    }
}
