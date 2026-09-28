# Appouse.Safetalk

.NET 8 / .NET 9 için **sunucudan sunucuya (B2B) güvenli haberleşme** kütüphanesi. İstemci tarafında giden
HTTP isteklerini **HMAC-SHA256** ile imzalar, sunucu tarafında bu imzaları istek controller'a ulaşmadan doğrular.

- İmza yalnızca body'yi değil, **HTTP metodu + path/query + timestamp + body** üçlüsünü kapsar.
- `HMACSHA256.HashData` (tek atımlık statik API), küçük harf hex çıktı, `CryptographicOperations.FixedTimeEquals` ile sabit zamanlı karşılaştırma.
- ±5 dakikalık timestamp penceresi ve isteğe bağlı **replay cache** ile tekrar saldırılarına karşı koruma.
- İstek gövdesi pooled bellek üzerinden imzalanır; anahtar ve gövde bellekten sıfırlanarak havuza iade edilir.
- `IHttpClientFactory` entegrasyonu, hazır middleware, endpoint bazlı kontrol ve `[Authorize]` desteği.
- Trimming / Native AOT uyumlu, `TreatWarningsAsErrors` ile derlenir.

## Paketler

| Paket | İçerik | Bağımlılık |
|---|---|---|
| `Appouse.Safetalk.Abstractions` | Sözleşmeler: `IHmacSignatureService`, `IHmacSecretProvider`, `IHmacReplayCache`, `SafetalkHeaderNames` | Yok |
| `Appouse.Safetalk.Core` | Kanonikleştirme (`CanonicalRequestBuffer`) ve `HmacSha256SignatureService` | Abstractions |
| `Appouse.Safetalk.Client` | `HmacSigningHandler` (DelegatingHandler), `AddHmacClient(...)`, `AddHmacSigning(...)` | Core, Microsoft.Extensions.Http |
| `Appouse.Safetalk.Server` | `HmacAuthenticationMiddleware`, `AddHmacServer(...)`, `UseHmacAuthentication()`, `AddAuthentication().AddHmac()` | Core, ASP.NET Core |

> Secret deposunu veya replay cache'i Infrastructure katmanında implement ediyorsanız yalnızca
> `Appouse.Safetalk.Abstractions` paketine referans vermeniz yeterlidir; ASP.NET Core bağımlılığı gelmez.

## Protokol

Her istekte üç header gönderilir:

| Header | Değer |
|---|---|
| `X-Client-Id` | İstemci kimliği (en fazla 256 yazdırılabilir ASCII karakter) |
| `X-Timestamp` | İmzalama anındaki Unix zamanı, **saniye** (UTC), örn. `1700000000` |
| `X-Signature` | Kanonik isteğin HMAC-SHA256 imzası, **küçük harf hex** (64 karakter) |

İmzalanan **kanonik istek**, aşağıdaki metnin UTF-8 byte'larıdır (ayraç `\n`, yani LF):

```text
{HTTP-METOD}\n{PATH-VE-QUERY}\n{TIMESTAMP}\n{BODY}
```

| Bileşen | Kural |
|---|---|
| `HTTP-METOD` | Büyük harf: `GET`, `POST`, ... |
| `PATH-VE-QUERY` | İstek hattında gönderilen hedef, olduğu gibi: `/api/orders?id=5`. Percent-encoding'ler istemcinin gönderdiği haliyle korunur (`/api/m%C3%BC%C5%9Fteri`). Fragment (`#...`) gönderilmez. Yalnızca origin-form (`/` ile başlayan) hedefler kabul edilir. |
| `TIMESTAMP` | `X-Timestamp` header'ının birebir değeri |
| `BODY` | Gövdenin kablo üzerinden gönderilen **ham byte'ları**; gövde yoksa boş |

Örnek — `POST /api/orders?id=5`, timestamp `1700000000`, body `{"productCode":"SKU-42"}`:

```text
POST
/api/orders?id=5
1700000000
{"productCode":"SKU-42"}
```

**Anahtar:** HMAC anahtarı, paylaşılan secret metninin UTF-8 byte'larıdır. En az 32 byte kriptografik rastgele veri
kullanın (örn. `Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))` çıktısı secret olarak kullanılabilir).

## İstemci (Client)

### Tek satırla kurulum (appsettings)

```json
"OrdersApi": {
  "BaseAddress": "https://api.example.com/",
  "ClientId": "partner-a",
  "Secret": "<Key Vault / User Secrets>"
}
```

```csharp
builder.Services.AddHmacClient<OrdersApiClient>(builder.Configuration.GetSection("OrdersApi"));
```

Bu çağrı typed client'ı `IHttpClientFactory`'ye kaydeder, `HmacSigningHandler`'ı pipeline'a ekler, `BaseAddress`'i
uygular ve seçenekleri uygulama açılışında doğrular (`ValidateOnStart`). Section yeniden yüklendiğinde (örneğin Key Vault'ta
secret döndürüldüğünde) yeni değer **restart gerekmeden** bir sonraki istekte kullanılır.

Typed client imzalama ile ilgilenmez:

```csharp
public sealed class OrdersApiClient(HttpClient httpClient)
{
    public Task<HttpResponseMessage> CreateAsync(CreateOrderRequest request, CancellationToken ct)
        => httpClient.PostAsJsonAsync("api/orders", request, ct);
}
```

### Diğer kayıt biçimleri

```csharp
// Kod ile (delegate bir kez çalışır; rotation için config overload'ını kullanın)
services.AddHmacClient<OrdersApiClient>(options =>
{
    options.ClientId = "partner-a";
    options.Secret = configuration["Safetalk:Secret"]!;
    options.BaseAddress = new Uri("https://api.example.com/");
});

// Arayüzlü typed client
services.AddHmacClient<IOrdersApi, OrdersApiClient>(configuration.GetSection("OrdersApi"));

// İsimli client → IHttpClientFactory.CreateClient("orders")
services.AddHmacClient("orders", configuration.GetSection("OrdersApi"));

// Mevcut bir named/typed client'a imzalama eklemek
services.AddHttpClient<LegacyClient>().AddHmacSigning(configuration.GetSection("OrdersApi"));

// DI olmadan
using var http = new HttpClient(new HmacSigningHandler(options) { InnerHandler = new SocketsHttpHandler() });
```

### Davranış

- **Resilience (Polly):** İmzalama handler'ı, ekleme sırasından bağımsız olarak her zaman ağa en yakın handler'dır.
  `AddHmacClient(...).AddStandardResilienceHandler()` veya `AddStandardHedgingHandler()` zincirlerinde her deneme (hedging
  klonları dahil) **yeniden imzalanır**. Aynı isteğin denemeleri aynı saniyeye denk gelse bile timestamp atomik olarak
  artırılır; böylece denemeler hiçbir zaman aynı imzayı taşımaz ve sunucunun replay korumasına takılmaz.
- **Hedging ve retry kapsamı:** Bu garanti, retry/hedging handler'ı aynı `IHttpClientBuilder` üzerinde (pipeline'ın
  *içinde*) kayıtlı olduğunda geçerlidir. Pipeline'a girmeden önce oluşturulan denemeler (dışarıdaki bir DelegatingHandler,
  `HttpClient.SendAsync` etrafındaki Polly, gRPC retry) bağımsız isteklerdir; aynı saniyede imzalanırlarsa aynı imzayı taşırlar.
- **Tüm client'lar:** `services.ConfigureHttpClientDefaults(b => b.AddHmacSigning(...))` factory'deki, kendi imzalama kaydı
  *olmayan* her client'ı imzalar (üçüncü taraf servislere giden çağrılar dahil); bilinçli olarak kullanın. Bir client'ın kendi
  `AddHmacSigning`/`AddHmacClient` kaydı varsa, kayıt sırasından bağımsız olarak o geçerlidir ve defaults'un `BaseAddress`'i ona
  uygulanmaz; pipeline'da her zaman tek bir imzalayıcı bulunur. Uygulamanın `AddHttpMessageHandler(() => new HmacSigningHandler(...))`
  ile kendisinin eklediği bir imzalayıcıya defaults dokunmaz.
- **Tekrarlanan kayıtlar:** Aynı client için `AddHmacSigning` iki kez çağrılırsa imzalama handler'ı değiştirilir, ancak options
  kayıtları birikimlidir: sonraki kayıt yalnızca kendi verdiği değerleri geçersiz kılar.
- **BaseAddress önceliği:** `ConfigureHttpClient(c => c.BaseAddress = ...)` ile açıkça verilen adres, `ConfigureHttpClientDefaults`
  içinde verilmiş olsa bile, options'taki `BaseAddress`'ten önce gelir. Global bir varsayılan adres kullanıyorsanız istemciye özel
  adresi de `ConfigureHttpClient` ile verin.
- **İçerik:** `ByteArrayContent`, `StringContent`, `FormUrlEncodedContent`, `ReadOnlyMemoryContent` doğrudan imzalanır.
  Tekrar okunamayan içerikler (`StreamContent`, `JsonContent`, multipart, ...) bir kez serileştirilip imzalanan byte'larla
  değiştirilir; gönderilen byte'lar imzalanan byte'larla birebir aynıdır.
- **Senkron `HttpClient.Send`** de imzalanır.
- **Yönlendirmeler:** Otomatik takip edilen redirect'ler aynı imzayı yeni hedefe taşır ve genellikle 401 alır. B2B
  istemcilerinde `AllowAutoRedirect = false` önerilir:
  `.ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false })`.

## Sunucu (Server)

### Tek satırla kurulum (appsettings)

```json
"Safetalk": {
  "AllowedClockSkew": "00:05:00",
  "MaxBodySize": 1048576,
  "EnableReplayProtection": true,
  "EnforcementMode": "AllRequests",
  "Clients": {
    "partner-a": "<secret>",
    "partner-b": { "Secret": "<secret>" }
  }
}
```

```csharp
builder.Services.AddProblemDetails(); // (opsiyonel) 401/413 yanıtları RFC 9457 formatında yazılır
builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));

var app = builder.Build();

app.UseHmacAuthentication();   // routing'den sonra, endpoint'lerden önce
app.UseAuthorization();        // açıkça ve HMAC'ten SONRA çağırın (aşağıya bakın)

app.MapHealthChecks("/health").SkipHmacValidation();
app.MapControllers();
```

`Clients` bölümündeki secret'lar `ConfigurationHmacSecretProvider` ile okunur, config reload'larını izler ve client id'leri
büyük/küçük harfe duyarlı (ordinal) eşleştirir. Bir client'ı tüm kaynaklarda (appsettings, Key Vault, environment variables)
**aynı biçimde** ve **aynı yazımla** tanımlayın: bir kaynakta string, diğerinde `{ "Secret": ... }` olarak tanımlanan client
belirsiz kabul edilir, hata loglanır ve istekleri reddedilir (fail closed).

### Kod ile kurulum ve kendi secret provider'ınız

```csharp
builder.Services
    .AddHmacServer(options =>
    {
        options.AllowedClockSkew = TimeSpan.FromMinutes(5); // varsayılan
        options.MaxBodySize = 4 * 1024 * 1024;              // varsayılan, aşılırsa 413
    })
    .AddSecretProvider<DatabaseSecretProvider>()            // veritabanı / Key Vault (varsayılan: scoped)
    .AddReplayProtection();                                 // opsiyonel
```

```csharp
public sealed class DatabaseSecretProvider(PartnerDbContext db, IMemoryCache cache) : IHmacSecretProvider
{
    public async ValueTask<string?> GetSecretAsync(string clientId, CancellationToken cancellationToken = default)
    {
        string cacheKey = $"safetalk:secret:{clientId}";
        if (cache.TryGetValue(cacheKey, out string? cached))
        {
            return cached;
        }

        var partner = await db.Partners
            .Where(p => p.ClientId == clientId && p.IsActive)
            .Select(p => new { p.ClientId, p.HmacSecret })
            .FirstOrDefaultAsync(cancellationToken);

        // SQL Server'ın varsayılan collation'ı büyük/küçük harfe duyarsızdır: kimliği ordinal olarak doğrulayın.
        string? secret = partner is not null && string.Equals(partner.ClientId, clientId, StringComparison.Ordinal)
            ? partner.HmacSecret
            : null;

        // Yalnızca bulunan secret'lar, yalnızca süreç içi bellekte önbelleğe alınır: rastgele client id'ler cache'i
        // şişiremez ve secret'lar Redis gibi paylaşımlı bir cache'e hiç yazılmaz.
        if (secret is not null)
        {
            cache.Set(cacheKey, secret, TimeSpan.FromMinutes(5));
        }

        return secret;
    }
}
```

Sunucu, `X-Client-Id` değeri 256 karakteri aşıyorsa veya yazdırılabilir ASCII dışında karakter içeriyorsa provider'ı hiç
çağırmadan isteği reddeder.

`null` dönmek istemcinin bilinmediği / pasif olduğu anlamına gelir ve istek 401 ile reddedilir.
Diğer seçenekler: `.AddSecretsFromConfiguration(section)`, `.AddInMemorySecrets(dictionary)`,
`.AddSecretProvider(sp => ..., ServiceLifetime.Singleton)`.

### Doğrulama akışı

Kontroller ucuzdan pahalıya sıralanır:

1. `X-Client-Id`, `X-Timestamp`, `X-Signature` header'ları tam olarak bir kez bulunmalıdır; client id en fazla 256 yazdırılabilir ASCII karakterdir.
2. Timestamp formatı ve ±`AllowedClockSkew` penceresi kontrol edilir.
3. Beyan edilen `Content-Length`, `MaxBodySize` sınırıyla karşılaştırılır. Bu ucuz DoS koruması secret sorgusundan önce yapılır.
4. İstek hedefinin origin-form olduğu ve imzasız bir `X-HTTP-Method-Override` bulunmadığı doğrulanır.
5. `IHmacSecretProvider` ile secret alınır.
6. Gövde `EnableBuffering()` ile tamamen bellekte (diske taşmadan) ve asenkron okunur, ardından `Position = 0` yapılır. Bellek, beyan edilen `Content-Length`'e göre değil gelen byte kadar büyür.
7. İmza sabit zamanlı karşılaştırılır.
8. Replay koruması açıksa tazelik yeniden kontrol edilir ve imza cache'e kaydedilir.

Her istek **bir kez** doğrulanır: sonuç istek boyunca saklanır; middleware, `AddHmac()` scheme'i, kendi kodunuz ve
`UseExceptionHandler`/`UseStatusCodePagesWithReExecute` ile yeniden çalıştırma aynı sonucu kullanır. Client id'ler gizli
değildir; yanıt kodları ve süreleri bir client id'nin tanınıp tanınmadığını ele verebilir. Kimlik doğrulanmadan önce
yapılan işleri sınırlamak için HMAC middleware'inden önce IP bazlı rate limiting kullanın.

Başarısız istekler anında **401 Unauthorized** (`WWW-Authenticate: HMAC-SHA256`), limit aşan gövdeler **413** ile
sonlandırılır; hata nedeni loglanır ama yanıtta ifşa edilmez. Başarılı isteklerde doğrulanmış istemci hazırdır:

```csharp
string clientId = HttpContext.GetHmacClientId()!;   // veya User.Identity!.Name / User.FindFirst("client_id")
```

### Hangi uçlar korunur? (endpoint bazlı kontrol)

| Mod | Davranış |
|---|---|
| `AllRequests` (varsayılan) | Middleware'e ulaşan her istek imzalı olmalı. Muafiyet: `[SkipHmacValidation]` / `.SkipHmacValidation()` |
| `MarkedEndpointsOnly` | Yalnızca `[RequireHmacValidation]` / `.RequireHmacValidation()` ile işaretli uçlar korunur |

```csharp
builder.Services.AddHmacServer(o => o.EnforcementMode = HmacEnforcementMode.MarkedEndpointsOnly)
    .AddSecretsFromConfiguration(builder.Configuration.GetSection("Safetalk:Clients"));

app.MapGroup("/api/b2b").RequireHmacValidation();      // tüm grup korunur
app.MapGet("/api/public/ping", () => "pong");          // korunmaz

[RequireHmacValidation]                                // controller seviyesinde
public sealed class PartnerOrdersController : ControllerBase { ... }
```

Öncelik kuralı:
- Attribute'lar (`[RequireHmacValidation]`, `[SkipHmacValidation]`) convention'lardan (`.RequireHmacValidation()`,
  `.SkipHmacValidation()`) önce gelir. Örneğin `app.MapControllers().SkipHmacValidation()` gibi geniş bir convention,
  controller üzerindeki açık bir `[RequireHmacValidation]`'ı asla ezmez.
- Her türün kendi içinde en spesifik olan kazanır: action attribute'u controller attribute'unu, endpoint convention'ı
  route group convention'ını geçersiz kılar.
- `[SkipHmacValidation]` kalıtılmaz (fail closed): temel controller'a veya temel virtual metoda yazılan skip, türetilmiş
  controller'lara ve override'lara geçmez. `[RequireHmacValidation]` ise kalıtılır. Buna bağlı iki not:
  - Temel sınıfta tanımlanıp **override edilmeyen** bir action kendi skip'ini her türetilmiş controller'da korur; bunu kaldırmak
    için action'ı override edin.
  - Temel sınıftan kalıtılan bir `[RequireHmacValidation]`, sınıf veya override seviyesindeki bir skip ile kaldırılamaz; bunun
    için action seviyesinde `[SkipHmacValidation]` kullanın.

Endpoint metadata'sı yalnızca middleware routing'den **sonra** çalıştığında okunabilir (`WebApplication`'da varsayılan). `UseRouting()`
middleware'den sonra eklenmişse bu açılışta tespit edilir, uyarı loglanır ve **tüm istekler doğrulanır** (fail closed).
Sıranın belirlenemediği durumlarda (`UseWhen`/`Map` dalı, endpoint'leri yalnızca `Map` dallarında tanımlı bir uygulama,
`UseMiddleware` ile manuel kayıt) endpoint'i seçilmemiş istekler de her modda doğrulanır; eşleşmeyen route'lar 404 yerine 401
alır. Bunu önlemek için dalı `UseRouting()` sonrasına koyun. Çalışma sırasında bir endpoint'in ancak middleware'den sonra seçildiği
görülürse bu bir kez loglanır ve o andan itibaren tüm istekler doğrulanır.
Alternatif olarak pipeline dallandırılabilir:
`app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/api/b2b"), b => b.UseHmacAuthentication());`

### `[Authorize]` ve policy'ler

`AddControllers()` / `AddAuthorization()` kullanan uygulamalarda `WebApplication`, `app.UseAuthorization()` açıkça çağrılmazsa
authorization middleware'ini **kullanıcı middleware'lerinden önce** ekler. Bu yüzden `app.UseAuthorization()` çağrısını
`UseHmacAuthentication()`'dan hemen sonra yapın. Policy başarısız olduğunda doğru 401/403 dönmesi için HMAC'i bir
authentication scheme olarak da kaydedin:

```csharp
builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk"));
builder.Services.AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme).AddHmac();
builder.Services.AddAuthorization(o => o.AddPolicy("PartnerA", p => p.RequireClaim("client_id", "partner-a")));

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/orders", ...).RequireAuthorization("PartnerA");
```

`AddHmac()` scheme'i imzalı istekleri kendisi de doğrulayabilir; bu durumda `UseHmacAuthentication()` zorunlu değildir.
Middleware ile birlikte kullanıldığında aynı istek (başarılı da olsa başarısız da olsa) iki kez doğrulanmaz.

### Pipeline notları

- `UseHmacAuthentication()` çağrısını gövdeyi değiştiren middleware'lerden (örn. `UseRequestDecompression()`) **önce** yapın;
  imza kablodaki byte'ları kapsar. Aksi halde istek `ContentLengthMismatch` ile reddedilir.
- `X-HTTP-Method-Override` header'ı imzalanmaz. Bu header'ı taşıyan istekler, `UseHttpMethodOverride()` onu routing'den önce
  uygulamadıysa reddedilir; routing'den sonra değiştirilen bir metot da, seçilen endpoint o metodu kabul etmediği için reddedilir.
  Override header'ı varken endpoint'in metodu açıkça listelemesi gerekir: herhangi bir metodu kabul eden (`Map`, `MapFallback`,
  yalnızca `[Route]` taşıyan action) endpoint'lere override'lı istekler reddedilir.
  Method override'ı HMAC korumalı uçlarda kullanmamanız önerilir; kullanmanız gerekiyorsa yalnızca **header** varyantını
  `UseHttpMethodOverride()` → `UseRouting()` → `UseHmacAuthentication()` sırasıyla kullanın (partner override edilen metodu imzalar).
  HMAC aynı zamanda varsayılan authentication scheme ise `app.UseAuthentication()` çağrısını da `UseHttpMethodOverride()`'dan sonra
  açıkça yapın. Gövdeyi okuyan middleware'ler (**form-field** override varyantı, `UseAntiforgery()`) `UseHmacAuthentication()`'dan
  sonra çalışmalıdır; aksi halde istek `BodyAlreadyConsumed` ile reddedilir.
- `UseExceptionHandler` / `UseStatusCodePagesWithReExecute` ile yeniden çalıştırılan istekler ikinci kez doğrulanmaz.
- Reverse proxy path'i yeniden yazıyorsa (örn. prefix siliyorsa) `options.RequestTargetResolver` ile imzada kullanılacak
  origin-form hedefi belirleyin.
- **Testler:** `TestServer` / `WebApplicationFactory` ham istek hedefini (`RawTarget`) sağlamaz; hedef çözümlenmiş path'ten
  yeniden kurulur. Percent-encode edilmiş ayrılmış karakter içeren path'ler (`%40`, `%3A`, `%2B` ...) bu yüzden yalnızca
  Kestrel / IIS / HTTP.sys üzerinde doğrulanır.

### Replay koruması

Timestamp penceresi tek başına, yakalanan bir isteğin 5 dakika içinde tekrar gönderilmesini engellemez.
Replay koruması açıkken kabul edilen her imza pencere süresince hatırlanır ve aynı isteğin ikinci kez işlenmesi engellenir.
Kayıtlar yalnızca **imza** ile anahtarlanır. `X-Client-Id` imzalanmadığı için anahtara dahil edilmez; aksi halde aynı istek
client id'nin farklı yazımlarıyla (örn. `Partner-A`) tekrar oynatılabilirdi. Replay koruması açıkken `AllowedClockSkew` config
reload ile anında **daraltılabilir**; ilk istekte geçerli olan değerin ötesine **genişletme** ise restart sonrası uygulanır (uyarı
loglanır). Önceden kaydedilmiş replay kayıtlarının ömrü geriye dönük uzatılamadığından, runtime'da genişletme daha önce kabul
edilmiş isteklerin tekrar oynatılmasına izin verirdi. Paylaşımlı (Redis gibi) bir replay cache kullanıyorsanız pencereyi restart
veya rolling deploy ile genişletmek de, değişiklikten önceki `(yeni - eski)` süre içinde kabul edilmiş istekleri tekrar
oynatılabilir bırakır: yeni pencereyi, eski pencere + 30 sn geçtikten sonra devreye alın.

Varsayılan `InMemoryHmacReplayCache` **tek instance** için geçerlidir. Birden fazla instance çalışıyorsa paylaşımlı bir
depo kullanın:

```csharp
public sealed class RedisReplayCache(IConnectionMultiplexer redis) : IHmacReplayCache
{
    public async ValueTask<bool> TryAddAsync(string signature, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        TimeSpan ttl = expiresAt - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero) return false; // fail closed

        // SET key value NX PX ttl — atomik "yoksa ekle"
        return await redis.GetDatabase().StringSetAsync($"safetalk:replay:{signature}", 1, ttl, When.NotExists);
    }
}

builder.Services.AddHmacServer(builder.Configuration.GetSection("Safetalk")).AddReplayProtection<RedisReplayCache>();
```

Aynı istemcinin aynı saniye içinde byte'ı byte'ına aynı iki *farklı* isteği aynı imzayı üretir; ikincisi reddedilir.
Bu tür istekleri gönderen istemciler gövdeye veya query'ye benzersiz bir istek kimliği eklemelidir. (Aynı isteğin retry ve
hedging denemeleri bundan etkilenmez; Appouse.Safetalk istemcisi timestamp'i artırarak yeniden imzalar.)

## Partner entegrasyonu (diğer diller)

**Bash / OpenSSL**

```bash
ts=$(date +%s)
body='{"productCode":"SKU-42","quantity":3}'
path='/api/orders?id=5'
sig=$(printf 'POST\n%s\n%s\n%s' "$path" "$ts" "$body" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

curl -X POST "https://api.example.com$path" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: partner-a" -H "X-Timestamp: $ts" -H "X-Signature: $sig" \
  --data-binary "$body"
```

**Python**

```python
import hashlib, hmac, json, time, requests

secret = "..."
path = "/api/orders?id=5"
body = json.dumps({"productCode": "SKU-42", "quantity": 3}, separators=(",", ":")).encode()
ts = str(int(time.time()))

canonical = b"\n".join([b"POST", path.encode(), ts.encode(), body])
signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()

requests.post(
    "https://api.example.com" + path,
    data=body,  # imzalanan byte'ların aynısı gönderilmeli
    headers={"Content-Type": "application/json", "X-Client-Id": "partner-a",
             "X-Timestamp": ts, "X-Signature": signature},
)
```

Tanı için `CanonicalRequest.Format(method, pathAndQuery, timestamp, body)` beklenen kanonik metni üretir.

## Güvenlik notları

- Her zaman **HTTPS** kullanın. HMAC bütünlük ve kimlik doğrulaması sağlar, gizlilik sağlamaz.
- Secret'ları kaynak kodda veya `appsettings.json` içinde tutmayın; Key Vault / Secrets Manager / User Secrets kullanın.
- Sunucu ile istemci saatlerini NTP ile senkron tutun; pencere dışındaki istekler reddedilir.
- `MaxBodySize`, kimliği henüz doğrulanmamış istekler için belleğe alınabilecek gövde boyutunu sınırlar. `N` byte'lık bir gövdenin
  doğrulanması yaklaşık `2N` geçici bellek ve 2'nin kuvvetine yuvarlanmış pooled bir buffer kullanır; sınırı partnerlerinizin
  gerçekte gönderdiği boyuta göre düşürün. Kestrel limitlerini (`MaxConcurrentConnections`, `Http2.MaxStreamsPerConnection`, `MinRequestBodyDataRate`) ve
  reverse proxy'nizin istek buffer'lama ayarlarını da derinlemesine savunma olarak yapılandırın.
- `IHmacSecretProvider` implementasyonları client id'yi **ordinal** eşleştirmelidir; bu değer kimliğin (claim) kendisidir.

## Yapılandırma referansı

**`HmacClientOptions`**

| Özellik | Açıklama |
|---|---|
| `ClientId` | `X-Client-Id` olarak gönderilir (zorunlu, en fazla 256 yazdırılabilir ASCII karakter, başta/sonda boşluk yok) |
| `Secret` | HMAC anahtarı (zorunlu) |
| `BaseAddress` | (opsiyonel) `HttpClient.BaseAddress`, mutlak `http`/`https` URI; `ConfigureHttpClient` ile verilen adres önceliklidir |

**`HmacServerOptions`**

| Özellik | Varsayılan | Açıklama |
|---|---|---|
| `AllowedClockSkew` | 5 dk | Timestamp'in sunucu saatinden sapabileceği en fazla süre (1 sn – 1 gün) |
| `MaxBodySize` | 4 MiB | Doğrulama için bellekte tutulacak en büyük gövde; aşılırsa 413 |
| `EnforcementMode` | `AllRequests` | `AllRequests` veya `MarkedEndpointsOnly` |
| `EnableReplayProtection` | `false` | `AddReplayProtection()` ile de açılır |
| `RequestTargetResolver` | `null` | İmzada kullanılacak origin-form path+query'yi özelleştirir (varsayılan: istemcinin gönderdiği ham hedef) |

## Geliştirme

```bash
dotnet build Appouse.Safetalk.slnx
dotnet test  Appouse.Safetalk.slnx
dotnet pack  Appouse.Safetalk.slnx -c Release -o artifacts

# Örnekler
dotnet run --project samples/Appouse.Safetalk.Samples.Server
dotnet run --project samples/Appouse.Safetalk.Samples.Client
```

## Lisans

[MIT](LICENSE) © 2026 Appouse Software Solutions
