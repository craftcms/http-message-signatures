<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

use HttpMessageSignatures\Exception\InvalidKeyException;

/**
 * Ed25519 signature algorithm.
 */
class Ed25519 implements AlgorithmInterface
{
    private string $privateKey;
    private ?string $publicKey;

    public function __construct(string $privateKey, ?string $publicKey = null)
    {
        if (!extension_loaded('sodium')) {
            throw new \RuntimeException('Ed25519 requires the sodium extension');
        }

        if (empty($privateKey)) {
            throw new InvalidKeyException('Ed25519 private key cannot be empty');
        }

        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    public function sign(string $data): string
    {
        $keyPair = sodium_crypto_sign_seed_keypair(
            substr($this->privateKey, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES)
        );

        if ($keyPair === false) {
            throw new InvalidKeyException('Failed to create Ed25519 key pair');
        }

        $signature = sodium_crypto_sign_detached($data, $keyPair);
        return base64_encode($signature);
    }

    public function verify(string $data, string $signature): bool
    {
        $publicKey = $this->getPublicKey();
        $decodedSignature = base64_decode($signature, true);

        if ($decodedSignature === false) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($decodedSignature, $data, $publicKey);
    }

    public function getAlgorithmId(): string
    {
        return 'ed25519';
    }

    private function getPublicKey(): string
    {
        if ($this->publicKey !== null) {
            return $this->publicKey;
        }

        $keyPair = sodium_crypto_sign_seed_keypair(
            substr($this->privateKey, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES)
        );

        if ($keyPair === false) {
            throw new InvalidKeyException('Failed to create Ed25519 key pair');
        }

        return sodium_crypto_sign_publickey($keyPair);
    }
}

