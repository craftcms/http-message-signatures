<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

/**
 * Default values used throughout the library.
 */
final class DefaultValues
{
    public const string DEFAULT_SIGNATURE_ID = 'sig1';
    public const int DEFAULT_HTTPS_PORT = 443;
    public const int DEFAULT_HTTP_PORT = 80;

    private function __construct()
    {
        // This class cannot be instantiated
    }
}
