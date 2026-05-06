<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

use HttpMessageSignatures\Exception\InvalidKeyException;
use OpenSSLAsymmetricKey;

/**
 * RSASSA-PKCS1-v1_5 using SHA-256 signature algorithm (rsa-v1_5-sha256).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421.html#name-rsassa-pkcs1-v1_5-using-sha
 * @see https://www.iana.org/assignments/http-message-signatures/http-message-signatures.xhtml
 */
class RsaSha256 implements AlgorithmInterface
{
    private OpenSSLAsymmetricKey $privateKey;

    private ?OpenSSLAsymmetricKey $publicKey;

    public function __construct(
        OpenSSLAsymmetricKey|string $privateKey,
        OpenSSLAsymmetricKey|string|null $publicKey = null,
    )
    {
        $this->privateKey = $this->resolvePrivateKey($privateKey);
        $this->publicKey = $publicKey !== null ? $this->resolvePublicKey($publicKey) : null;
    }

    public function sign(string $data): string
    {
        $signature = '';
        $success = openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        if (!$success) {
            throw new InvalidKeyException('Failed to sign data with RSA key: ' . openssl_error_string());
        }

        return $signature;
    }

    public function verify(string $data, string $signature): bool
    {
        $publicKey = $this->getPublicKey();
        $result = openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        return $result === 1;
    }

    public function getAlgorithmId(): string
    {
        return 'rsa-v1_5-sha256';
    }

    private function getPublicKey(): OpenSSLAsymmetricKey
    {
        if ($this->publicKey !== null) {
            return $this->publicKey;
        }

        $details = openssl_pkey_get_details($this->privateKey);

        if ($details === false || !isset($details['key'])) {
            throw new InvalidKeyException('Could not extract public key from private key');
        }

        $publicKey = openssl_pkey_get_public($details['key']);
        if ($publicKey === false) {
            throw new InvalidKeyException('Invalid public key: ' . openssl_error_string());
        }

        return $publicKey;
    }

    private function resolvePrivateKey(OpenSSLAsymmetricKey|string $key): OpenSSLAsymmetricKey
    {
        if ($key instanceof OpenSSLAsymmetricKey) {
            return $key;
        }

        $resource = openssl_pkey_get_private($key);
        if ($resource === false) {
            throw new InvalidKeyException('Invalid private key: ' . openssl_error_string());
        }

        return $resource;
    }

    private function resolvePublicKey(OpenSSLAsymmetricKey|string $key): OpenSSLAsymmetricKey
    {
        if ($key instanceof OpenSSLAsymmetricKey) {
            return $key;
        }

        $resource = openssl_pkey_get_public($key);
        if ($resource === false) {
            throw new InvalidKeyException('Invalid public key: ' . openssl_error_string());
        }

        return $resource;
    }
}
