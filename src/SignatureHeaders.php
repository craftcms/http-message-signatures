<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

/**
 * HTTP signature header names as defined in RFC 9421.
 */
final class SignatureHeaders
{
    public const string SIGNATURE_INPUT = 'Signature-Input';
    public const string SIGNATURE = 'Signature';

    private function __construct()
    {
        // This class cannot be instantiated
    }
}
