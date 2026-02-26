<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

/**
 * Derived component identifiers as defined in RFC 9421.
 */
final class DerivedComponents
{
    public const string METHOD = '@method';
    public const string PATH = '@path';
    public const string QUERY = '@query';
    public const string AUTHORITY = '@authority';
    public const string SCHEME = '@scheme';
    public const string TARGET_URI = '@target-uri';
    public const string REQUEST_TARGET = '@request-target';
    public const string STATUS = '@status';

    public const string QUERY_PARAM_PREFIX = '@query-param';

    private function __construct()
    {
        // This class cannot be instantiated
    }
}
