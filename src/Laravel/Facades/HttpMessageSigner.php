<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Laravel\Facades;

use HttpMessageSignatures\Signer;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \Psr\Http\Message\MessageInterface sign(\Psr\Http\Message\MessageInterface $message, array $components, array $options = [])
 *
 * @see \HttpMessageSignatures\Signer
 */
class HttpMessageSigner extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return Signer::class;
    }
}

