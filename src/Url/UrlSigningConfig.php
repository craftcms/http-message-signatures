<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

final class UrlSigningConfig
{
    /**
     * @param  array<string>  $components  Component identifiers to cover (default: full URL)
     * @param  string  $signatureParam  Query parameter name for the signature
     * @param  int|null  $created  Unix timestamp for 'created' param (null = omit)
     * @param  int|null  $expiresAfter  Seconds after $created until expiration (null = no expiry, requires $created)
     * @param  string|null  $keyid  Key identifier
     * @param  string|null  $nonce  Nonce value
     * @param  string|null  $tag  Tag value
     */
    public function __construct(
        public readonly array $components = ['@target-uri'],
        public readonly string $signatureParam = 'signature',
        public readonly ?int $created = null,
        public readonly ?int $expiresAfter = null,
        public readonly ?string $keyid = null,
        public readonly ?string $nonce = null,
        public readonly ?string $tag = 'url-signature',
    ) {}

    /**
     * Create a config with the current timestamp as 'created'.
     *
     * Convenience factory that sets created=time() so callers don't have to.
     *
     * @param  array<string>  $components  Component identifiers to cover
     * @param  int|null  $expiresAfter  Seconds until expiration (null = no expiry)
     */
    public static function withCurrentTime(
        array $components = ['@target-uri'],
        string $signatureParam = 'signature',
        ?int $expiresAfter = null,
        ?string $keyid = null,
        ?string $nonce = null,
        ?string $tag = 'url-signature',
    ): self {
        return new self(
            components: $components,
            signatureParam: $signatureParam,
            created: time(),
            expiresAfter: $expiresAfter,
            keyid: $keyid,
            nonce: $nonce,
            tag: $tag,
        );
    }
}
