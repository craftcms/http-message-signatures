<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\SignatureException;
use HttpMessageSignatures\SignatureBase;
use League\Uri\Modifier;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;

final class UrlSigner
{
    private const SIGNATURE_INPUT_PARAM = 'signature-input';

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
     * Sign a URL and return the URL with a signature query parameter appended.
     *
     * Accepts a plain URL string or a PSR-7 RequestInterface.
     * When a RequestInterface is passed, its method is preserved — this allows
     * signing URLs for non-GET methods (e.g. POST form actions) when @method
     * is included in the components list.
     *
     * When a string is passed, a synthetic GET request is created internally.
     *
     * @param  string|RequestInterface  $url  The URL (or request) to sign
     * @return string The signed URL with a signature query parameter
     *
     * @throws SignatureException
     */
    public function sign(string|RequestInterface $url): string
    {
        if ($this->config->components === []) {
            throw new SignatureException('At least one component must be specified');
        }

        // Resolve method and URI string from input
        if ($url instanceof RequestInterface) {
            $method = $url->getMethod();
            $uriString = (string) $url->getUri();
        } else {
            $method = 'GET';
            $uriString = $url;
        }

        // Strip any existing signature artifacts.
        $cleanUrl = Modifier::wrap($uriString)
            ->removeQueryPairsByKey($this->config->signatureParam, self::SIGNATURE_INPUT_PARAM)
            ->toString();

        // Create request with resolved method and clean URL
        $request = $this->requestFactory->createRequest($method, $cleanUrl);

        $signatureInput = UrlSignatureInput::fromConfig($this->config, $this->algorithm);

        // Build signature base string
        $signatureBaseString = $this->signatureBase->build($signatureInput, $request);

        // Sign
        $rawSignature = $this->algorithm->sign($signatureBaseString);

        // Append signature query param
        return Modifier::wrap($cleanUrl)
            ->appendQueryParameters([
                $this->config->signatureParam => Base64Url::encode($rawSignature),
            ])
            ->toString();
    }
}
