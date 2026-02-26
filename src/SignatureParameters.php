<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

/**
 * Signature parameter names as defined in RFC 9421.
 */
final class SignatureParameters
{
    public const string CREATED = 'created';
    public const string EXPIRES = 'expires';
    public const string NONCE = 'nonce';
    public const string ALGORITHM = 'alg';
    public const string KEY_ID = 'keyid';
    public const string TAG = 'tag';

    /**
     * Canonical order of parameters for deterministic serialization.
     *
     * @var array<int, string>
     */
    public const array CANONICAL_ORDER = [
        self::CREATED,
        self::EXPIRES,
        self::NONCE,
        self::ALGORITHM,
        self::KEY_ID,
        self::TAG,
    ];

    private function __construct()
    {
        // This class cannot be instantiated
    }
}
