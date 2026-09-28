namespace Appouse.Safetalk.Server;

/// <summary>
/// The reason a signed request was rejected.
/// </summary>
public enum HmacValidationFailure
{
    /// <summary>
    /// The request was not rejected.
    /// </summary>
    None = 0,

    /// <summary>
    /// <c>X-Client-Id</c>, <c>X-Timestamp</c> or <c>X-Signature</c> is missing, empty or repeated.
    /// </summary>
    MissingHeaders,

    /// <summary>
    /// <c>X-Timestamp</c> is not a non-negative integer number of seconds.
    /// </summary>
    InvalidTimestamp,

    /// <summary>
    /// <c>X-Timestamp</c> is outside the allowed clock skew window (expired or too far in the future).
    /// </summary>
    TimestampOutOfRange,

    /// <summary>
    /// The secret provider does not know the client.
    /// </summary>
    UnknownClient,

    /// <summary>
    /// The request body exceeds <see cref="HmacServerOptions.MaxBodySize"/>.
    /// </summary>
    PayloadTooLarge,

    /// <summary>
    /// The request target is not in origin-form (<c>/path?query</c>). Absolute-form and asterisk-form targets are
    /// interpreted differently by the server than they are signed, so they are never accepted.
    /// </summary>
    InvalidRequestTarget,

    /// <summary>
    /// The number of body bytes differs from the <c>Content-Length</c> header. This happens when the body was truncated,
    /// or when a middleware that replaces <c>HttpRequest.Body</c> (for example request decompression) runs before HMAC
    /// validation.
    /// </summary>
    ContentLengthMismatch,


    /// <summary>
    /// The signature is malformed or does not match the canonical request.
    /// </summary>
    InvalidSignature,

    /// <summary>
    /// The request was already accepted once (replay attack).
    /// </summary>
    ReplayDetected,

    /// <summary>
    /// The request carries an <c>X-HTTP-Method-Override</c> header naming a method other than the verified one, or the
    /// verified method is not accepted by the endpoint selected by routing (the method was rewritten after routing).
    /// When an override header is present, the endpoint must list the method explicitly (any-method and fallback
    /// endpoints are rejected). The override is not signed, so it could otherwise route a signed request to a
    /// different handler.
    /// </summary>
    UnsignedMethodOverride,

    /// <summary>
    /// The request body was consumed before validation and cannot be rewound (for example a form read by the form-field
    /// variant of <c>UseHttpMethodOverride()</c>). Run such middleware after <c>UseHmacAuthentication()</c>.
    /// </summary>
    BodyAlreadyConsumed,
}
