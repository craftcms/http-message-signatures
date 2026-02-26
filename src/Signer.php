<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\SignatureException;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Signs HTTP messages according to RFC 9421.
 */
class Signer
{
    private AlgorithmInterface $algorithm;
    private StructuredFieldParser $parser;
    private SignatureBaseStringBuilder $baseStringBuilder;

    public function __construct(
        AlgorithmInterface $algorithm,
        ?StructuredFieldParser $parser = null,
        ?SignatureBaseStringBuilder $baseStringBuilder = null
    ) {
        $this->algorithm = $algorithm;
        $this->parser = $parser ?? new StructuredFieldParser();
        $this->baseStringBuilder = $baseStringBuilder ?? new SignatureBaseStringBuilder();
    }

    /**
     * Sign an HTTP message.
     *
     * @param MessageInterface $message The message to sign
     * @param array<string> $components The component identifiers to include in the signature
     * @param array<string, mixed> $options Signing options:
     *   - keyid: string (required) - Key identifier
     *   - signatureId: string (default: "sig1") - Signature identifier
     *   - created: int|null - Creation timestamp
     *   - expires: int|null - Expiration timestamp
     *   - nonce: string|null - Nonce value
     *   - tag: string|null - Tag value
     *   - originalRequest: RequestInterface|null - Original request (for response signing)
     * @return MessageInterface The signed message
     * @throws SignatureException
     */
    public function sign(MessageInterface $message, array $components, array $options = []): MessageInterface
    {
        $this->ensureComponentsAreProvided($components);
        $keyId = $this->extractRequiredKeyId($options);
        $signatureId = $this->extractSignatureId($options);
        $signatureParameters = $this->buildSignatureParameters($options, $keyId);
        $originalRequest = $options['originalRequest'] ?? null;

        $signatureBaseString = $this->buildSignatureBaseString(
            $components,
            $message,
            $originalRequest,
            $signatureParameters
        );

        $signatureValue = $this->algorithm->sign($signatureBaseString);

        return $this->attachSignatureHeaders(
            $message,
            $signatureId,
            $components,
            $signatureParameters,
            $signatureValue
        );
    }

    private function ensureComponentsAreProvided(array $components): void
    {
        if (empty($components)) {
            throw new SignatureException('At least one component must be specified');
        }
    }

    private function extractRequiredKeyId(array $options): string
    {
        $keyId = $options['keyid'] ?? null;
        if (empty($keyId)) {
            throw new SignatureException('keyid is required');
        }

        return $keyId;
    }

    private function extractSignatureId(array $options): string
    {
        return $options['signatureId'] ?? DefaultValues::DEFAULT_SIGNATURE_ID;
    }

    private function buildSignatureParameters(array $options, string $keyId): array
    {
        $parameters = [
            SignatureParameters::CREATED => $options['created'] ?? time(),
            SignatureParameters::KEY_ID => $keyId,
        ];

        $this->addOptionalParameterIfPresent($parameters, SignatureParameters::EXPIRES, $options['expires'] ?? null);
        $this->addOptionalParameterIfPresent($parameters, SignatureParameters::NONCE, $options['nonce'] ?? null);
        $this->addOptionalParameterIfPresent($parameters, SignatureParameters::TAG, $options['tag'] ?? null);
        $this->addAlgorithmIfNotDefault($parameters);

        return $parameters;
    }

    private function addOptionalParameterIfPresent(array &$parameters, string $key, mixed $value): void
    {
        if ($value !== null) {
            $parameters[$key] = $value;
        }
    }

    private function addAlgorithmIfNotDefault(array &$parameters): void
    {
        $algorithmId = $this->algorithm->getAlgorithmId();
        $isDefaultAlgorithm = $algorithmId === 'hmac-sha256';

        if (!$isDefaultAlgorithm) {
            $parameters[SignatureParameters::ALGORITHM] = $algorithmId;
        }
    }

    private function buildSignatureBaseString(
        array $components,
        MessageInterface $message,
        ?RequestInterface $originalRequest,
        array $signatureParameters
    ): string {
        return $this->baseStringBuilder->build(
            $components,
            $message,
            $originalRequest,
            $signatureParameters
        );
    }

    private function attachSignatureHeaders(
        MessageInterface $message,
        string $signatureId,
        array $components,
        array $signatureParameters,
        string $signatureValue
    ): MessageInterface {
        $signatureInputValue = $this->parser->formatSignatureInput($signatureId, $components, $signatureParameters);
        $message = $this->appendHeader($message, SignatureHeaders::SIGNATURE_INPUT, $signatureInputValue);

        $signatureHeaderValue = $this->parser->formatSignature($signatureId, $signatureValue);
        $message = $this->appendHeader($message, SignatureHeaders::SIGNATURE, $signatureHeaderValue);

        return $message;
    }

    /**
     * Append a header to the message, preserving existing values.
     */
    private function appendHeader(MessageInterface $message, string $headerName, string $headerValue): MessageInterface
    {
        $existingHeaderValues = $message->getHeader($headerName);
        $hasExistingHeaders = !empty($existingHeaderValues);

        if ($hasExistingHeaders) {
            $combinedHeaderValue = implode(', ', $existingHeaderValues) . ', ' . $headerValue;
            return $message->withHeader($headerName, $combinedHeaderValue);
        }

        return $message->withHeader($headerName, $headerValue);
    }
}
