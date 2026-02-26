<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Laravel;

use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Verifier;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;

if (!function_exists('HttpMessageSignatures\Laravel\sign_http_message')) {
    /**
     * Sign an HTTP message using the configured signer.
     *
     * @param \Psr\Http\Message\MessageInterface $message
     * @param array<string> $components
     * @param array<string, mixed> $options
     * @return \Psr\Http\Message\MessageInterface
     */
    function sign_http_message($message, array $components = [], array $options = []): \Psr\Http\Message\MessageInterface
    {
        $signer = App::make(Signer::class);
        $components = $components ?: config('http-message-signatures.default_components', []);
        $options['keyid'] = $options['keyid'] ?? config('http-message-signatures.default_key_id', 'default');
        $options['signatureId'] = $options['signatureId'] ?? config('http-message-signatures.default_signature_id', 'sig1');

        return $signer->sign($message, $components, $options);
    }
}

if (!function_exists('HttpMessageSignatures\Laravel\verify_http_message')) {
    /**
     * Verify an HTTP message signature.
     *
     * @param \Psr\Http\Message\MessageInterface $message
     * @param string|null $signatureId
     * @return bool
     */
    function verify_http_message($message, ?string $signatureId = null): bool
    {
        $verifier = App::make(Verifier::class);

        return $verifier->verify($message, $signatureId);
    }
}

if (!function_exists('HttpMessageSignatures\Laravel\sign_request')) {
    /**
     * Sign a Laravel Request instance.
     *
     * @param \Illuminate\Http\Request $request
     * @param array<string> $components
     * @param array<string, mixed> $options
     * @return \Illuminate\Http\Request
     */
    function sign_request(Request $request, array $components = [], array $options = []): Request
    {
        $signedMessage = sign_http_message($request, $components, $options);

        // Copy signature headers to Laravel request
        if ($signedMessage->hasHeader('Signature-Input')) {
            $request->headers->set('Signature-Input', $signedMessage->getHeaderLine('Signature-Input'));
        }
        if ($signedMessage->hasHeader('Signature')) {
            $request->headers->set('Signature', $signedMessage->getHeaderLine('Signature'));
        }

        return $request;
    }
}
