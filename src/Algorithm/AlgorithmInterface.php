<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

/**
 * Interface for signature algorithms.
 */
interface AlgorithmInterface
{
    /**
     * Sign the given data.
     *
     * @param string $data The data to sign
     * @return string The signature
     */
    public function sign(string $data): string;

    /**
     * Verify the given signature against the data.
     *
     * @param string $data The data to verify
     * @param string $signature The signature to verify
     * @return bool True if the signature is valid
     */
    public function verify(string $data, string $signature): bool;

    /**
     * Get the algorithm identifier (e.g., "hmac-sha256", "rsa-sha256", "ed25519").
     *
     * @return string
     */
    public function getAlgorithmId(): string;
}

