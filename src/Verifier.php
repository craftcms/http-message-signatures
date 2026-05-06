<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Bakame\Http\StructuredFields\Bytes;
use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\VerificationException;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Verifies HTTP message signatures according to RFC 9421.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2
 */
class Verifier
{
    private SignatureBase $signatureBase;

    public function __construct(
        private readonly AlgorithmInterface $algorithm,
        ?SignatureBase $signatureBase = null,
    ) {
        $this->signatureBase = $signatureBase ?? new SignatureBase();
    }

    /**
     * Verify a signature on an HTTP message.
     *
     * @param  MessageInterface  $message  The message to verify
     * @param  string|null  $signatureId  The signature identifier to verify (default: first found)
     * @param  RequestInterface|null  $originalRequest  The original request (for response verification)
     * @return bool True if the signature is valid
     *
     * @throws VerificationException
     */
    public function verify(
        MessageInterface $message,
        ?string $signatureId = null,
        ?RequestInterface $originalRequest = null,
    ): bool {
        // Extract and parse the Signature-Input and Signature headers
        $signatureInputHeader = $this->extractRequiredHeader($message, 'Signature-Input');
        $signatureHeader = $this->extractRequiredHeader($message, 'Signature');

        $signatureInputDict = $this->parseDictionary($signatureInputHeader, 'Signature-Input');
        $signatureDict = $this->parseDictionary($signatureHeader, 'Signature');

        // Resolve which signature to verify
        $resolvedId = $this->resolveSignatureId($signatureId, $signatureInputDict);

        // Extract the InnerList (from Signature-Input) and Item (from Signature)
        $signatureInput = $this->extractSignatureInput($signatureInputDict, $resolvedId);
        $signatureItem = $this->extractSignatureValue($signatureDict, $resolvedId);

        // Check expiration
        $this->ensureNotExpired($signatureInput);

        // Rebuild the signature base string
        $signatureBaseString = $this->signatureBase->build($signatureInput, $message, $originalRequest);

        // Extract raw signature bytes
        $rawSignature = $this->extractRawSignatureBytes($signatureItem);

        // Verify
        $isValid = $this->algorithm->verify($signatureBaseString, $rawSignature);

        if (!$isValid) {
            throw new VerificationException('Signature verification failed');
        }

        return true;
    }

    private function extractRequiredHeader(MessageInterface $message, string $headerName): string
    {
        $headerValues = $message->getHeader($headerName);

        if ($headerValues === []) {
            throw new VerificationException("{$headerName} header not found");
        }

        return implode(', ', $headerValues);
    }

    private function parseDictionary(string $headerValue, string $headerName): Dictionary
    {
        try {
            return Dictionary::fromHttpValue($headerValue);
        } catch (\Throwable $e) {
            throw new VerificationException(
                "Failed to parse {$headerName} header as structured field dictionary: " . $e->getMessage(),
                0,
                $e,
            );
        }
    }

    private function resolveSignatureId(?string $requestedId, Dictionary $signatureInputDict): string
    {
        if ($requestedId !== null) {
            return $requestedId;
        }

        // Get the first key from the dictionary
        $keys = $signatureInputDict->keys();
        if ($keys === []) {
            throw new VerificationException('No signature inputs found');
        }

        return $keys[0];
    }

    private function extractSignatureInput(Dictionary $dict, string $signatureId): InnerList
    {
        if (!$dict->hasKeys($signatureId)) {
            throw new VerificationException("Signature input '{$signatureId}' not found");
        }

        $member = $dict->getByKey($signatureId);

        if (!$member instanceof InnerList) {
            throw new VerificationException("Signature input '{$signatureId}' is not an inner list");
        }

        return $member;
    }

    private function extractSignatureValue(Dictionary $dict, string $signatureId): Item
    {
        if (!$dict->hasKeys($signatureId)) {
            throw new VerificationException("Signature '{$signatureId}' not found");
        }

        $member = $dict->getByKey($signatureId);

        if (!$member instanceof Item) {
            throw new VerificationException("Signature '{$signatureId}' is not an item");
        }

        return $member;
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

    private function extractRawSignatureBytes(Item $signatureItem): string
    {
        $value = $signatureItem->value();

        if (!$value instanceof Bytes) {
            throw new VerificationException('Signature value is not a byte sequence');
        }

        return $value->decoded();
    }
}
