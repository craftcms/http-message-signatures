<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

use HttpMessageSignatures\Exception\InvalidKeyException;

/**
 * HMAC-SHA256 signature algorithm.
 */
class HmacSha256 implements AlgorithmInterface
{
    private string $secretKey;

    public function __construct(string $secretKey)
    {
        if (empty($secretKey)) {
            throw new InvalidKeyException('HMAC secret key cannot be empty');
        }

        $this->secretKey = $secretKey;
    }

    public function sign(string $data): string
    {
        $signature = hash_hmac('sha256', $data, $this->secretKey, true);
        return base64_encode($signature);
    }

    public function verify(string $data, string $signature): bool
    {
        $expectedSignature = $this->sign($data);
        return hash_equals($expectedSignature, $signature);
    }

    public function getAlgorithmId(): string
    {
        return 'hmac-sha256';
    }
}

