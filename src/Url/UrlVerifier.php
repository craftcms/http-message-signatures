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

        $rawSignature = Base64Url::decode((string) $encodedSignature);

        if ($this->config->components === []) {
            throw new VerificationException('At least one component must be specified');
        }

        $signatureInput = UrlSignatureInput::fromConfig($this->config, $this->algorithm);

        // Check expiration
        $this->ensureNotExpired($signatureInput);

        // Strip signature param to get the clean URL
        $cleanUrl = Modifier::wrap($uriString)
            ->removeQueryPairsByKey($this->config->signatureParam)
            ->toString();

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
