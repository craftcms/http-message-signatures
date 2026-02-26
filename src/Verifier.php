<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\VerificationException;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Verifies HTTP message signatures according to RFC 9421.
 */
class Verifier
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
     * Verify a signature on an HTTP message.
     *
     * @param MessageInterface $message The message to verify
     * @param string|null $signatureId The signature identifier to verify (default: first found)
     * @param RequestInterface|null $originalRequest The original request (for response verification)
     * @return bool True if the signature is valid
     * @throws VerificationException
     */
    public function verify(
        MessageInterface $message,
        ?string $signatureId = null,
        ?RequestInterface $originalRequest = null
    ): bool {
        $signatureInputHeader = $this->extractRequiredHeader($message, SignatureHeaders::SIGNATURE_INPUT);
        $signatureHeader = $this->extractRequiredHeader($message, SignatureHeaders::SIGNATURE);

        $parsedSignatureInputs = $this->parser->parseSignatureInput($signatureInputHeader);
        $parsedSignatures = $this->parser->parseSignature($signatureHeader);

        $this->ensureSignatureInputsExist($parsedSignatureInputs);
        $this->ensureSignaturesExist($parsedSignatures);

        $resolvedSignatureId = $this->resolveSignatureId($signatureId, $parsedSignatureInputs);
        $signatureInput = $this->extractSignatureInput($parsedSignatureInputs, $resolvedSignatureId);
        $signatureValue = $this->extractSignatureValue($parsedSignatures, $resolvedSignatureId);

        $this->ensureSignatureHasNotExpired($signatureInput);

        $signatureBaseString = $this->buildSignatureBaseString(
            $signatureInput['components'],
            $message,
            $originalRequest,
            $signatureInput['params']
        );

        $this->verifySignatureValue($signatureBaseString, $signatureValue);

        return true;
    }

    private function extractRequiredHeader(MessageInterface $message, string $headerName): string
    {
        $headerValues = $message->getHeader($headerName);
        if (empty($headerValues)) {
            throw new VerificationException("{$headerName} header not found");
        }

        return implode(', ', $headerValues);
    }

    private function ensureSignatureInputsExist(array $signatureInputs): void
    {
        if (empty($signatureInputs)) {
            throw new VerificationException('No signature inputs found');
        }
    }

    private function ensureSignaturesExist(array $signatures): void
    {
        if (empty($signatures)) {
            throw new VerificationException('No signatures found');
        }
    }

    private function resolveSignatureId(?string $requestedSignatureId, array $availableSignatureInputs): string
    {
        if ($requestedSignatureId !== null) {
            return $requestedSignatureId;
        }

        return array_key_first($availableSignatureInputs) ?? throw new VerificationException(
            'No signature ID available'
        );
    }

    private function extractSignatureInput(array $signatureInputs, string $signatureId): array
    {
        if (!isset($signatureInputs[$signatureId])) {
            throw new VerificationException("Signature input '{$signatureId}' not found");
        }

        return $signatureInputs[$signatureId];
    }

    private function extractSignatureValue(array $signatures, string $signatureId): string
    {
        if (!isset($signatures[$signatureId])) {
            throw new VerificationException("Signature '{$signatureId}' not found");
        }

        return $signatures[$signatureId];
    }

    private function ensureSignatureHasNotExpired(array $signatureInput): void
    {
        $expiresParameter = $signatureInput['params'][SignatureParameters::EXPIRES] ?? null;
        if ($expiresParameter === null) {
            return;
        }

        $expirationTimestamp = (int) $expiresParameter;
        $currentTimestamp = time();
        $hasExpired = $currentTimestamp > $expirationTimestamp;

        if ($hasExpired) {
            throw new VerificationException('Signature has expired');
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

    private function verifySignatureValue(string $signatureBaseString, string $signatureValue): void
    {
        $isValid = $this->algorithm->verify($signatureBaseString, $signatureValue);

        if (!$isValid) {
            throw new VerificationException('Signature verification failed');
        }
    }
}
