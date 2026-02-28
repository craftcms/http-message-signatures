<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use Bakame\Http\StructuredFields\InnerList;
use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\VerificationException;
use HttpMessageSignatures\SignatureBase;
use Psr\Http\Message\RequestFactoryInterface;
use Uri\Rfc3986\Uri;

final class UrlVerifier
{
    private SignatureBase $signatureBase;

    public function __construct(
        private readonly AlgorithmInterface $algorithm,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly UrlSigningConfig $config = new UrlSigningConfig(),
        ?SignatureBase $signatureBase = null,
    ) {
        $this->signatureBase = $signatureBase ?? new SignatureBase();
    }

    /**
     * Verify a signed URL.
     *
     * @param  string|Uri  $url  The signed URL to verify
     * @return bool True if the signature is valid
     *
     * @throws VerificationException
     */
    public function verify(string|Uri $url): bool
    {
        $uri = $url instanceof Uri ? $url : new Uri((string) $url);

        // Extract the signature
        $encodedSignature = UrlQueryHelper::extractParam($uri, $this->config->signatureParam);

        if ($encodedSignature === null) {
            throw new VerificationException("Signature parameter '{$this->config->signatureParam}' not found in URL");
        }

        $rawSignature = UrlQueryHelper::base64urlDecode($encodedSignature);

        // Extract and parse signature-input
        $signatureInputValue = UrlQueryHelper::extractParam($uri, $this->config->signatureInputParam);

        if ($signatureInputValue === null) {
            throw new VerificationException(
                "Signature input parameter '{$this->config->signatureInputParam}' not found in URL",
            );
        }

        $signatureInput = $this->parseSignatureInput($signatureInputValue);

        // Check expiration
        $this->ensureNotExpired($signatureInput);

        // Strip signature params to get the clean URL
        $cleanUri = UrlQueryHelper::stripParams($uri, [
            $this->config->signatureParam,
            $this->config->signatureInputParam,
        ]);

        // Create synthetic GET request from the clean URL
        $request = $this->requestFactory->createRequest('GET', $cleanUri->toString());

        // Rebuild signature base string
        $signatureBaseString = $this->signatureBase->build($signatureInput, $request);

        // Verify
        if (!$this->algorithm->verify($signatureBaseString, $rawSignature)) {
            throw new VerificationException('URL signature verification failed');
        }

        return true;
    }

    private function parseSignatureInput(string $value): InnerList
    {
        try {
            return InnerList::fromHttpValue($value);
        } catch (\Throwable $e) {
            throw new VerificationException(
                'Failed to parse signature-input as structured field inner list: ' . $e->getMessage(),
                0,
                $e,
            );
        }
    }

    private function ensureNotExpired(InnerList $signatureInput): void
    {
        $expires = $signatureInput->parameterByKey('expires');

        if ($expires === null) {
            return;
        }

        if (!is_int($expires)) {
            throw new VerificationException('Invalid expires parameter');
        }

        if ($expires < time()) {
            throw new VerificationException('Signature has expired');
        }
    }
}
