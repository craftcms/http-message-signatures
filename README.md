# HTTP Message Signatures (RFC 9421)

A PHP 8.1+ implementation of [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) as specified in RFC 9421.

## Features

- ✅ RFC 9421 signing and verification support
- ✅ **PSR-7 compliant** - Works with any PSR-7 HTTP message implementation
- ✅ Support for multiple signature algorithms:
  - HMAC-SHA256
  - RSA-SHA256
  - Ed25519
- ✅ Signature creation and verification
- ✅ Structured fields parsing for `signature-input` and `signature` headers
- ✅ Component derivation (headers, query parameters, request target, etc.)
- ✅ Immutable message handling (respects PSR-7 immutability)

## Installation

```bash
composer require craftcms/http-message-signatures
```

## Requirements

- PHP 8.1 or higher
- PSR-7 HTTP message implementation (e.g., `guzzlehttp/psr7`, `nyholm/psr7`, `slim/psr7`)

## Dependencies

This package uses well-maintained, industry-standard libraries:

- **[bakame/http-structured-fields](https://packagist.org/packages/bakame/http-structured-fields)** - For parsing and formatting HTTP Structured Fields (RFC 8941) used in signature headers

## Usage

### Creating a Signature

```php
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Algorithm\HmacSha256;
use GuzzleHttp\Psr7\Request;

// Create a PSR-7 request
$request = new Request(
    'POST',
    'https://api.example.com/resource',
    [
        'Host' => 'api.example.com',
        'Content-Type' => 'application/json',
        'Date' => gmdate('D, d M Y H:i:s \G\M\T'),
    ],
    '{"data":"value"}'
);

// Create signer with HMAC-SHA256 algorithm
$signer = new Signer(new HmacSha256('your-secret-key'));

// Sign the request (returns a new immutable PSR-7 message)
$signedRequest = $signer->sign(
    $request,
    ['@method', '@path', '@authority', 'content-type', 'date'],
    [
        'keyid' => 'my-key-id',
        'signatureId' => 'sig1',
        'created' => time(),
        'expires' => time() + 300, // Optional: 5 minutes
    ]
);

// The original request is unchanged (PSR-7 immutability)
// $signedRequest is a new instance with Signature and Signature-Input headers
```

### Verifying a Signature

```php
use HttpMessageSignatures\Verifier;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\VerificationException;

$verifier = new Verifier(new HmacSha256('your-secret-key'));

try {
    // Verify the signature (returns true if valid)
    $isValid = $verifier->verify($signedRequest);
    
    if ($isValid) {
        echo "Signature is valid!\n";
    }
} catch (VerificationException $e) {
    echo "Verification failed: " . $e->getMessage() . "\n";
}
```

### Signing URLs

Use `UrlSigner` and `UrlVerifier` when the signature needs to live in the URL instead of HTTP headers.

RFC 9421 does not define a signed URL format. This package provides URL signing as a convenience API that applies the same component derivation, signature base, parameters, and algorithms to a URL-carried signature.

```php
use Http\Factory\Guzzle\RequestFactory;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Url\UrlSigner;
use HttpMessageSignatures\Url\UrlSigningConfig;
use HttpMessageSignatures\Url\UrlVerifier;

$algorithm = new HmacSha256('your-secret-key');
$requestFactory = new RequestFactory();

$config = new UrlSigningConfig(
    components: ['@target-uri'],
    signatureParam: 'signature',
);

$signer = new UrlSigner($algorithm, $requestFactory, $config);
$verifier = new UrlVerifier($algorithm, $requestFactory, $config);

$signedUrl = $signer->sign('https://example.com/image.jpg?w=800');

if ($verifier->verify($signedUrl)) {
    echo "URL signature is valid!\n";
}
```

Signed URLs only include the configured signature query parameter. The component list and signature parameters are verifier policy, so the signer and verifier must be configured with the same `UrlSigningConfig`.

By default, URL signatures cover `@target-uri`, append a `signature` query parameter, and omit `created`/`expires`. Configure `components`, `signatureParam`, `created`, `expiresAfter`, `keyid`, `nonce`, or `tag` when those values are part of your URL signing policy.

```php
$config = UrlSigningConfig::withCurrentTime(
    components: ['@path', '@query'],
    signatureParam: 'sig',
    expiresAfter: 300,
);
```

When signing or verifying non-GET URLs, pass a PSR-7 `RequestInterface` so the request method can be included with `@method`.

### Using RSA-SHA256

```php
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Algorithm\RsaSha256;

// Load your private key (for signing)
$privateKey = file_get_contents('/path/to/private-key.pem');

// Optionally provide public key (for verification)
$publicKey = file_get_contents('/path/to/public-key.pem');

$signer = new Signer(new RsaSha256($privateKey, $publicKey));

$signedRequest = $signer->sign(
    $request,
    ['@method', '@path', '@authority', 'content-type'],
    ['keyid' => 'rsa-key-1']
);
```

### Using Ed25519

```php
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Algorithm\Ed25519;

// Ed25519 requires the sodium extension
$privateKey = sodium_crypto_sign_seed_keypair(...);
$publicKey = sodium_crypto_sign_publickey($privateKey);

$signer = new Signer(new Ed25519($privateKey, $publicKey));

$signedRequest = $signer->sign(
    $request,
    ['@method', '@path', '@authority'],
    ['keyid' => 'ed25519-key-1']
);
```

### Available Components

The following components can be included in signatures:

**Derived Components:**
- `@method` - HTTP method
- `@path` - Request path
- `@query` - Query string
- `@authority` - Host and port
- `@scheme` - URI scheme
- `@target-uri` - Full URI
- `@request-target` - Request target
- `@status` - Response status code (for responses)

**Headers:**
- Any header name (e.g., `content-type`, `date`, `authorization`)

**Query Parameters:**
- `@query-param;name="paramname"` - Specific query parameter

## PSR-7 Compliance

This package is fully PSR-7 compliant:

- Works with any PSR-7 implementation (`guzzlehttp/psr7`, `nyholm/psr7`, `slim/psr7`, etc.)
- Respects PSR-7 immutability - all methods return new message instances
- Uses only PSR-7 interfaces (`MessageInterface`, `RequestInterface`, `ResponseInterface`)
- No direct dependencies on specific PSR-7 implementations

## Testing

```bash
composer test
```

## Code Quality

```bash
# Run all checks (lint + PHPStan + tests)
composer check

# Lint code
composer lint

# Auto-fix lint issues
composer fix

# Static analysis
composer phpstan
```

## License

MIT
