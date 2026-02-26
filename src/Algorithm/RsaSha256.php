<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

use HttpMessageSignatures\Exception\InvalidKeyException;
use OpenSSLAsymmetricKey;

/**
 * RSA-SHA256 signature algorithm.
 */
class RsaSha256 implements AlgorithmInterface
{
    private OpenSSLAsymmetricKey|string $privateKey;
    private OpenSSLAsymmetricKey|string|null $publicKey;

    public function __construct(
        OpenSSLAsymmetricKey|string $privateKey,
        OpenSSLAsymmetricKey|string|null $publicKey = null
    ) {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    public function sign(string $data): string
    {
        $privateKey = $this->getPrivateKeyResource();
        $signature = '';
        $success = openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        if (!$success) {
            throw new InvalidKeyException('Failed to sign data with RSA key: ' . openssl_error_string());
        }

        return base64_encode($signature);
    }

    public function verify(string $data, string $signature): bool
    {
        $publicKey = $this->getPublicKeyResource();
        $decodedSignature = base64_decode($signature, true);

        if ($decodedSignature === false) {
            return false;
        }

        $result = openssl_verify($data, $decodedSignature, $publicKey, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }

    public function getAlgorithmId(): string
    {
        return 'rsa-sha256';
    }

    private function getPrivateKeyResource(): OpenSSLAsymmetricKey|string
    {
        if (is_resource($this->privateKey) || $this->privateKey instanceof OpenSSLAsymmetricKey) {
            return $this->privateKey;
        }

        $resource = openssl_pkey_get_private($this->privateKey);
        if ($resource === false) {
            throw new InvalidKeyException('Invalid private key: ' . openssl_error_string());
        }

        return $resource;
    }

    private function getPublicKeyResource(): OpenSSLAsymmetricKey|string
    {
        if ($this->publicKey !== null) {
            if (is_resource($this->publicKey) || $this->publicKey instanceof OpenSSLAsymmetricKey) {
                return $this->publicKey;
            }

            $resource = openssl_pkey_get_public($this->publicKey);
            if ($resource === false) {
                throw new InvalidKeyException('Invalid public key: ' . openssl_error_string());
            }

            return $resource;
        }

        // Try to extract public key from private key
        $privateKey = $this->getPrivateKeyResource();
        $details = openssl_pkey_get_details($privateKey);

        if ($details === false || !isset($details['key'])) {
            throw new InvalidKeyException('Could not extract public key from private key');
        }

        $publicKey = openssl_pkey_get_public($details['key']);
        if ($publicKey === false) {
            throw new InvalidKeyException('Invalid public key: ' . openssl_error_string());
        }

        return $publicKey;
    }
}

