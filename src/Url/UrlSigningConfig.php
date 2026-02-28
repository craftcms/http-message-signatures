<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

final class UrlSigningConfig
{
    /**
     * @param  array<string>  $components  Component identifiers to cover (default: full URL)
     * @param  string  $signatureParam  Query parameter name for the signature
     * @param  string  $signatureInputParam  Query parameter name for the signature input
     * @param  int|false|null  $created  Timestamp for 'created' param (null = current time, false = omit)
     * @param  int|null  $expiresAfter  Seconds until expiration (null = no expiry)
     * @param  string|null  $keyid  Key identifier
     * @param  string|null  $nonce  Nonce value
     * @param  string|null  $tag  Tag value
     */
    public function __construct(
        public readonly array $components = ['@target-uri'],
        public readonly string $signatureParam = 'signature',
        public readonly string $signatureInputParam = 'signature-input',
        public readonly int|false|null $created = null,
        public readonly ?int $expiresAfter = null,
        public readonly ?string $keyid = null,
        public readonly ?string $nonce = null,
        public readonly ?string $tag = 'url-signature',
    ) {}
}
