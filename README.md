# HTTP Message Signatures (RFC 9421)

A PHP 8.4+ implementation of [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) as specified in RFC 9421.

## Features

- ✅ Full RFC 9421 compliance
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
composer require timkelty/http-message-signatures
```

## Requirements

- PHP 8.4 or higher
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

## Laravel Integration

This package includes first-class Laravel support:

### Installation

```bash
composer require timkelty/http-message-signatures
```

### Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag=http-message-signatures-config
```

Configure your keys in `.env`:

```env
HTTP_SIGNATURE_ALGORITHM=hmac-sha256
HTTP_SIGNATURE_HMAC_SECRET_KEY=your-secret-key
HTTP_SIGNATURE_KEY_ID=my-key-id
```

### Usage

#### Using Facades

```php
use HttpMessageSignatures\Laravel\Facades\HttpMessageSigner;
use HttpMessageSignatures\Laravel\Facades\HttpMessageVerifier;

// Sign a request
$signedRequest = HttpMessageSigner::sign($request, [
    '@method', '@path', '@authority', 'content-type'
], ['keyid' => 'my-key']);

// Verify a request
$isValid = HttpMessageVerifier::verify($request);
```

#### Using Helper Functions

```php
use function HttpMessageSignatures\Laravel\sign_request;
use function HttpMessageSignatures\Laravel\sign_http_message;
use function HttpMessageSignatures\Laravel\verify_http_message;

// Sign a Laravel Request
$signedRequest = sign_request($request);

// Sign any HTTP message
$signedMessage = sign_http_message($message);

// Verify an HTTP message
$isValid = verify_http_message($message);
```

#### Using Dependency Injection

```php
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Verifier;

class MyController
{
    public function __construct(
        private Signer $signer,
        private Verifier $verifier
    ) {}

    public function sign(Request $request)
    {
        $signed = $this->signer->sign($request, [
            '@method', '@path', '@authority'
        ], ['keyid' => 'my-key']);

        return response()->json(['signed' => true]);
    }
}
```

### Service Provider

The package automatically registers a service provider. All classes are bound in the container and can be injected via dependency injection.

## PSR-7 Compliance

This package is fully PSR-7 compliant:

- Works with any PSR-7 implementation (`guzzlehttp/psr7`, `nyholm/psr7`, `slim/psr7`, etc.)
- Respects PSR-7 immutability - all methods return new message instances
- Uses only PSR-7 interfaces (`MessageInterface`, `RequestInterface`, `ResponseInterface`)
- No direct dependencies on specific PSR-7 implementations

## Development

### Running Tests

```bash
composer test
```

### Code Style

This project uses [Mago](https://github.com/carthage-software/mago) for formatting and linting:

```bash
composer fmt
composer lint
# or (auto-fix)
composer lint:fix
```

### Static Analysis

This project uses [PHPStan](https://phpstan.org/) for static analysis:

```bash
composer phpstan
# or
./vendor/bin/phpstan analyse
```

## License

MIT
