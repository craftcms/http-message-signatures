<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Algorithm;

use HttpMessageSignatures\Exception\InvalidKeyException;
use SodiumException;

/**
 * Ed25519 signature algorithm (ed25519).
 *
 * Supports both 32-byte seeds and 64-byte secret keys.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421.html#name-eddsa-using-curve25519
 */
class Ed25519 implements AlgorithmInterface
{
    /** @var non-empty-string */
    private string $secretKey;

    /** @var non-empty-string */
    private string $publicKey;

    /**
     * @param  non-empty-string  $privateKey  Either a 32-byte seed or a 64-byte Ed25519 secret key
     * @param  non-empty-string|null  $publicKey  32-byte public key (derived from private key if not provided)
     */
    public function __construct(string $privateKey, string $publicKey = null)
    {
        $keyLength = strlen($privateKey);

        if ($keyLength === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            // 32-byte seed: derive keypair
            try {
                $keypair = sodium_crypto_sign_seed_keypair($privateKey);
            } catch (SodiumException $e) {
                throw new InvalidKeyException('Invalid Ed25519 seed: ' . $e->getMessage(), 0, $e);
            }
            $this->secretKey = sodium_crypto_sign_secretkey($keypair);
            $this->publicKey = $publicKey ?? sodium_crypto_sign_publickey($keypair);
        } elseif ($keyLength === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            // 64-byte secret key: use directly
            $this->secretKey = $privateKey;
            $this->publicKey = $publicKey ?? sodium_crypto_sign_publickey_from_secretkey($privateKey);
        } else {
            throw new InvalidKeyException(
                'Ed25519 private key must be '
                . SODIUM_CRYPTO_SIGN_SEEDBYTES
                . ' bytes (seed) or '
                . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
                . ' bytes (secret key), got '
                . $keyLength,
            );
        }

        if ($publicKey !== null && strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKeyException(
                'Ed25519 public key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' bytes, got ' . strlen($publicKey),
            );
        }
    }

    public function sign(string $data): string
    {
        try {
            return sodium_crypto_sign_detached($data, $this->secretKey);
        } catch (SodiumException $e) {
            throw new InvalidKeyException('Ed25519 signing failed: ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(string $data, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }

        try {
            return sodium_crypto_sign_verify_detached($signature, $data, $this->publicKey);
        } catch (SodiumException) {
            return false;
        }
    }

    public function getAlgorithmId(): string
    {
        return 'ed25519';
    }
}
