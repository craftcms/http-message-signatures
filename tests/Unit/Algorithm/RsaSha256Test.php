<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit\Algorithm;

use HttpMessageSignatures\Algorithm\RsaSha256;
use HttpMessageSignatures\Exception\InvalidKeyException;
use PHPUnit\Framework\TestCase;

final class RsaSha256Test extends TestCase
{
    private string $privateKeyPem;

    private string $publicKeyPem;

    protected function setUp(): void
    {
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $resource = openssl_pkey_new($config);
        self::assertNotFalse($resource);
        openssl_pkey_export($resource, $privateKeyPem);
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $this->privateKeyPem = $privateKeyPem;
        $this->publicKeyPem = $details['key'];
    }

    public function testSignReturnsRawBinaryBytes(): void
    {
        $algorithm = new RsaSha256($this->privateKeyPem, $this->publicKeyPem);
        $signature = $algorithm->sign('test data');

        $this->assertIsString($signature);
        $this->assertGreaterThan(0, strlen($signature));
        $this->assertSame(256, strlen($signature));
    }

    public function testVerifyAcceptsRawBytesAndReturnsTrueForValidSignature(): void
    {
        $algorithm = new RsaSha256($this->privateKeyPem, $this->publicKeyPem);
        $signature = $algorithm->sign('test data');

        $this->assertTrue($algorithm->verify('test data', $signature));
    }

    public function testVerifyReturnsFalseForInvalidSignature(): void
    {
        $algorithm = new RsaSha256($this->privateKeyPem, $this->publicKeyPem);
        $signature = $algorithm->sign('test data');

        $this->assertFalse($algorithm->verify('different data', $signature));
    }

    public function testCanDerivePublicKeyFromPrivateKey(): void
    {
        $algorithm = new RsaSha256($this->privateKeyPem);
        $signature = $algorithm->sign('test data');

        $this->assertTrue($algorithm->verify('test data', $signature));
    }

    public function testValidatesKeysDuringConstruction(): void
    {
        $this->expectException(InvalidKeyException::class);
        new RsaSha256('not-a-valid-key');
    }

    public function testGetAlgorithmIdReturnsRsaV15Sha256(): void
    {
        $algorithm = new RsaSha256($this->privateKeyPem);
        $this->assertSame('rsa-v1_5-sha256', $algorithm->getAlgorithmId());
    }
}
