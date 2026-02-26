<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

use HttpMessageSignatures\Exception\InvalidKeyException;

/**
 * HMAC-SHA256 signature algorithm (hmac-sha256).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421.html#name-hmac-using-sha-256
 */
class HmacSha256 implements AlgorithmInterface
{
    private string $secretKey;

    public function __construct(string $secretKey)
    {
        if ($secretKey === '') {
            throw new InvalidKeyException('HMAC secret key cannot be empty');
        }

        $this->secretKey = $secretKey;
    }

    public function sign(string $data): string
    {
        return hash_hmac('sha256', $data, $this->secretKey, binary: true);
    }

    public function verify(string $data, string $signature): bool
    {
        $expected = $this->sign($data);

        return hash_equals($expected, $signature);
    }

    public function getAlgorithmId(): string
    {
        return 'hmac-sha256';
    }
}
