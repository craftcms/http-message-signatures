<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Parameters;
use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\SignatureException;
use HttpMessageSignatures\SignatureBase;
use HttpMessageSignatures\Signer;
use Psr\Http\Message\RequestFactoryInterface;
use Uri\Rfc3986\Uri;

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
     * @param  string|Uri  $url  The URL to sign
     * @return string The signed URL with signature and signature-input query parameters
     *
     * @throws SignatureException
     */
    public function sign(string|Uri $url): string
    {
        $uri = $url instanceof Uri ? $url : new Uri((string) $url);

        if ($this->config->components === []) {
            throw new SignatureException('At least one component must be specified');
        }

        // Strip any existing signature params
        $cleanUri = UrlQueryHelper::stripParams($uri, [
            $this->config->signatureParam,
            $this->config->signatureInputParam,
        ]);

        // Create synthetic GET request from the clean URL
        $request = $this->requestFactory->createRequest('GET', $cleanUri->toString());

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
        return UrlQueryHelper::appendParams($cleanUri, [
            $this->config->signatureInputParam => $signatureInput->toHttpValue(),
            $this->config->signatureParam => UrlQueryHelper::base64urlEncode($rawSignature),
        ]);
    }

    private function buildSignatureParameters(): Parameters
    {
        $params = [];

        $created = $this->config->created ?? time();

        if ($created !== false) {
            $params['created'] = (int) $created;
        }

        if ($this->config->expiresAfter !== null && $created !== false) {
            $params['expires'] = (int) $created + $this->config->expiresAfter;
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
}
