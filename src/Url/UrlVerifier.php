<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use Bakame\Http\StructuredFields\InnerList;
use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\VerificationException;
use HttpMessageSignatures\SignatureBase;
use League\Uri\Components\Query;
use League\Uri\Modifier;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;

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
     * Accepts a plain URL string or a PSR-7 RequestInterface.
     * When a RequestInterface is passed, its method is preserved for verification —
     * this is necessary when the signature covers @method.
     *
     * When a string is passed, a synthetic GET request is assumed.
     *
     * @param  string|RequestInterface  $url  The signed URL (or request) to verify
     * @return bool True if the signature is valid
     *
     * @throws VerificationException
     */
    public function verify(string|RequestInterface $url): bool
    {
        // Resolve method and URI string from input
        if ($url instanceof RequestInterface) {
            $method = $url->getMethod();
            $uriString = (string) $url->getUri();
        } else {
            $method = 'GET';
            $uriString = $url;
        }

        $query = Query::fromUri($uriString);

        // Extract the signature
        $encodedSignature = $query->parameter($this->config->signatureParam);

        if ($encodedSignature === null) {
            throw new VerificationException("Signature parameter '{$this->config->signatureParam}' not found in URL");
        }

        $rawSignature = self::base64urlDecode((string) $encodedSignature);

        // Extract and parse signature-input
        $signatureInputValue = $query->parameter($this->config->signatureInputParam);

        if ($signatureInputValue === null) {
            throw new VerificationException(
                "Signature input parameter '{$this->config->signatureInputParam}' not found in URL",
            );
        }

        $signatureInput = $this->parseSignatureInput((string) $signatureInputValue);

        // Check expiration
        $this->ensureNotExpired($signatureInput);

        // Strip signature params to get the clean URL
        $cleanUrl = Modifier::wrap($uriString)->removeQueryPairs(
            $this->config->signatureParam,
            $this->config->signatureInputParam,
        )->toString();

        // Create request with resolved method and clean URL
        $request = $this->requestFactory->createRequest($method, $cleanUrl);

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

    /**
     * Base64url decode (RFC 4648 Section 5).
     *
     * @throws VerificationException
     */
    private static function base64urlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw new VerificationException('Invalid base64url data');
        }

        return $decoded;
    }
}
