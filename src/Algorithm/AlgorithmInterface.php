<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

/**
 * Interface for signature algorithms used in HTTP Message Signatures (RFC 9421).
 *
 * Implementations MUST work with raw binary bytes:
 * - sign() accepts raw data and returns raw signature bytes
 * - verify() accepts raw data and raw signature bytes
 *
 * Base64 encoding/decoding is handled at the structured fields layer,
 * not within the algorithm implementations.
 */
interface AlgorithmInterface
{
    /**
     * Sign the given data.
     *
     * @param  string  $data  The data to sign (signature base string)
     * @return string Raw signature bytes (NOT base64 encoded)
     */
    public function sign(string $data): string;

    /**
     * Verify the given signature against the data.
     *
     * @param  string  $data  The data that was signed
     * @param  string  $signature  Raw signature bytes (NOT base64 encoded)
     * @return bool True if the signature is valid
     */
    public function verify(string $data, string $signature): bool;

    /**
     * Get the algorithm identifier as registered in the HTTP Signature Algorithms registry.
     *
     * @see https://www.iana.org/assignments/http-message-signatures/http-message-signatures.xhtml
     */
    public function getAlgorithmId(): string;
}
