<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Laravel\Facades;

use HttpMessageSignatures\Verifier;
use Illuminate\Support\Facades\Facade;

/**
 * @method static bool verify(\Psr\Http\Message\MessageInterface $message, ?string $signatureId = null, ?\Psr\Http\Message\RequestInterface $originalRequest = null)
 *
 * @see \HttpMessageSignatures\Verifier
 */
class HttpMessageVerifier extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return Verifier::class;
    }
}

