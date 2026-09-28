using System.Collections;
using Microsoft.Extensions.Http;

namespace Appouse.Safetalk.Client.Tests.Infrastructure;

/// <summary>
/// Records, for every pipeline the factory builds, each <see cref="DelegatingHandler"/> that any registration action
/// ever put into <see cref="HttpMessageHandlerBuilder.AdditionalHandlers"/> (through <c>Add</c>, <c>Insert</c> or the
/// indexer), including handlers that a later action removed again. Unlike <see cref="AdditionalHandlersRecorder"/>,
/// which only sees the final list, it therefore exposes handlers that were created and then replaced.
/// </summary>
/// <remarks>
/// It hands the registration actions a forwarding builder whose handler list reports every addition. Register it after
/// the clients so that it runs inside the factory's default logging filter.
/// </remarks>
internal sealed class HandlerAdditionRecorder : IHttpMessageHandlerBuilderFilter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, List<DelegatingHandler>> _added = new(StringComparer.Ordinal);

    /// <summary>
    /// Returns every handler added while the pipeline of <paramref name="name"/> was built, in order of addition.
    /// </summary>
    public IReadOnlyList<DelegatingHandler> AddedTo(string name)
    {
        lock (_gate)
        {
            Assert.True(_added.TryGetValue(name, out List<DelegatingHandler>? added), $"No pipeline was built for '{name}'.");
            return [.. added];
        }
    }

    public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next) => builder =>
    {
        var added = new List<DelegatingHandler>();
        next(new RecordingBuilder(builder, added));
        lock (_gate)
        {
            _added[builder.Name ?? string.Empty] = added;
        }
    };

    private sealed class RecordingBuilder(HttpMessageHandlerBuilder inner, List<DelegatingHandler> added) : HttpMessageHandlerBuilder
    {
        private readonly RecordingHandlerCollection _handlers = new(inner.AdditionalHandlers, added);

        public override string? Name
        {
            get => inner.Name;
            set
            {
                ArgumentNullException.ThrowIfNull(value);
                inner.Name = value;
            }
        }

        public override HttpMessageHandler PrimaryHandler
        {
            get => inner.PrimaryHandler;
            set => inner.PrimaryHandler = value;
        }

        public override IList<DelegatingHandler> AdditionalHandlers => _handlers;

        public override IServiceProvider Services => inner.Services;

        public override HttpMessageHandler Build() => inner.Build();
    }

    private sealed class RecordingHandlerCollection(IList<DelegatingHandler> inner, List<DelegatingHandler> added) : IList<DelegatingHandler>
    {
        public int Count => inner.Count;

        public bool IsReadOnly => inner.IsReadOnly;

        public DelegatingHandler this[int index]
        {
            get => inner[index];
            set
            {
                added.Add(value);
                inner[index] = value;
            }
        }

        public void Add(DelegatingHandler item)
        {
            added.Add(item);
            inner.Add(item);
        }

        public void Insert(int index, DelegatingHandler item)
        {
            added.Add(item);
            inner.Insert(index, item);
        }

        public void Clear() => inner.Clear();

        public bool Contains(DelegatingHandler item) => inner.Contains(item);

        public void CopyTo(DelegatingHandler[] array, int arrayIndex) => inner.CopyTo(array, arrayIndex);

        public IEnumerator<DelegatingHandler> GetEnumerator() => inner.GetEnumerator();

        public int IndexOf(DelegatingHandler item) => inner.IndexOf(item);

        public bool Remove(DelegatingHandler item) => inner.Remove(item);

        public void RemoveAt(int index) => inner.RemoveAt(index);

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
