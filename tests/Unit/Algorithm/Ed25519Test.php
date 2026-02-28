<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit\Algorithm;

use HttpMessageSignatures\Algorithm\Ed25519;
use HttpMessageSignatures\Exception\InvalidKeyException;
use PHPUnit\Framework\TestCase;

final class Ed25519Test extends TestCase
{
    private string $secretKey;

    private string $publicKey;

    private string $seed;

    protected function setUp(): void
    {
        $keypair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($keypair);
        $this->publicKey = sodium_crypto_sign_publickey($keypair);
        $this->seed = substr($this->secretKey, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES);
    }

    public function testSignReturnsRawBinaryBytesWith64ByteSecretKey(): void
    {
        $algorithm = new Ed25519($this->secretKey, $this->publicKey);
        $signature = $algorithm->sign('test data');

        $this->assertIsString($signature);
        $this->assertSame(SODIUM_CRYPTO_SIGN_BYTES, strlen($signature));
    }

    public function testSignReturnsRawBinaryBytesWith32ByteSeed(): void
    {
        $algorithm = new Ed25519($this->seed, $this->publicKey);
        $signature = $algorithm->sign('test data');

        $this->assertIsString($signature);
        $this->assertSame(SODIUM_CRYPTO_SIGN_BYTES, strlen($signature));
    }

    public function testVerifyWith64ByteSecretKey(): void
    {
        $algorithm = new Ed25519($this->secretKey, $this->publicKey);
        $signature = $algorithm->sign('test data');

        $this->assertTrue($algorithm->verify('test data', $signature));
    }

    public function testVerifyWith32ByteSeed(): void
    {
        $algorithm = new Ed25519($this->seed, $this->publicKey);
        $signature = $algorithm->sign('test data');

        $this->assertTrue($algorithm->verify('test data', $signature));
    }

    public function testSeedAndSecretKeyProduceTheSameSignature(): void
    {
        $algSeed = new Ed25519($this->seed, $this->publicKey);
        $algSecret = new Ed25519($this->secretKey, $this->publicKey);

        $this->assertSame($algSeed->sign('test data'), $algSecret->sign('test data'));
    }

    public function testDerivesPublicKeyFromSecretKeyWhenNotProvided(): void
    {
        $algorithm = new Ed25519($this->secretKey);
        $signature = $algorithm->sign('test data');

        $this->assertTrue($algorithm->verify('test data', $signature));
    }

    public function testDerivesPublicKeyFromSeedWhenNotProvided(): void
    {
        $algorithm = new Ed25519($this->seed);
        $signature = $algorithm->sign('test data');

        $this->assertTrue($algorithm->verify('test data', $signature));
    }

    public function testVerifyReturnsFalseForInvalidSignature(): void
    {
        $algorithm = new Ed25519($this->secretKey, $this->publicKey);
        $signature = $algorithm->sign('test data');

        $this->assertFalse($algorithm->verify('different data', $signature));
    }

    public function testThrowsOnInvalidKeyLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        new Ed25519('too-short');
    }

    public function testThrowsOnInvalidPublicKeyLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        new Ed25519($this->seed, 'bad-pub-key');
    }

    public function testGetAlgorithmIdReturnsEd25519(): void
    {
        $algorithm = new Ed25519($this->secretKey, $this->publicKey);
        $this->assertSame('ed25519', $algorithm->getAlgorithmId());
    }
}
