<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Parameters;
use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\SignatureException;
use HttpMessageSignatures\SignatureBase;
use HttpMessageSignatures\Signer;
use League\Uri\Modifier;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;

final class UrlSigner
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
     * Sign a URL and return the URL with signature query parameters appended.
     *
     * Accepts a plain URL string or a PSR-7 RequestInterface.
     * When a RequestInterface is passed, its method is preserved — this allows
     * signing URLs for non-GET methods (e.g. POST form actions) when @method
     * is included in the components list.
     *
     * When a string is passed, a synthetic GET request is created internally.
     *
     * @param  string|RequestInterface  $url  The URL (or request) to sign
     * @return string The signed URL with signature and signature-input query parameters
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

        // Strip any existing signature params
        $cleanUrl = Modifier::wrap($uriString)
            ->removeQueryPairs($this->config->signatureParam, $this->config->signatureInputParam)
            ->toString();

        // Create request with resolved method and clean URL
        $request = $this->requestFactory->createRequest($method, $cleanUrl);

        // Parse component identifiers
        $componentItems = array_map(Signer::parseComponentIdentifier(...), $this->config->components);

        // Build signature parameters
        $signatureParameters = $this->buildSignatureParameters();

        // Create InnerList
        $signatureInput = InnerList::fromAssociative($componentItems, $signatureParameters);

        // Build signature base string
        $signatureBaseString = $this->signatureBase->build($signatureInput, $request);

        // Sign
        $rawSignature = $this->algorithm->sign($signatureBaseString);

        // Append signature-input and signature query params
        return Modifier::wrap($cleanUrl)
            ->appendQueryParameters([
                $this->config->signatureInputParam => $signatureInput->toHttpValue(),
                $this->config->signatureParam => self::base64urlEncode($rawSignature),
            ])
            ->toString();
    }

    /**
     * @see Signer::buildSignatureParameters() for a similar implementation — consider
     *      extracting a shared builder if more signing surfaces are added.
     */
    private function buildSignatureParameters(): Parameters
    {
        $params = [];

        if ($this->config->created !== null) {
            $params['created'] = $this->config->created;
        }

        if ($this->config->expiresAfter !== null && $this->config->created !== null) {
            $params['expires'] = $this->config->created + $this->config->expiresAfter;
        }

        if ($this->config->nonce !== null) {
            $params['nonce'] = $this->config->nonce;
        }

        $algId = $this->algorithm->getAlgorithmId();

        if ($algId !== '') {
            $params['alg'] = $algId;
        }

        if ($this->config->keyid !== null) {
            $params['keyid'] = $this->config->keyid;
        }

        if ($this->config->tag !== null) {
            $params['tag'] = $this->config->tag;
        }

        return Parameters::fromAssociative($params);
    }

    /**
     * Base64url encode (RFC 4648 Section 5), no padding.
     */
    private static function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
