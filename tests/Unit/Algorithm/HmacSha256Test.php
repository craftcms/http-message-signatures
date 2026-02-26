<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit\Algorithm;

use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\InvalidKeyException;
use PHPUnit\Framework\TestCase;

final class HmacSha256Test extends TestCase
{
    public function testSignReturnsRawBinaryBytes(): void
    {
        $algorithm = new HmacSha256('test-secret-key');
        $signature = $algorithm->sign('test data');

        $this->assertIsString($signature);
        $this->assertSame(32, strlen($signature));
    }

    public function testSignProducesConsistentOutput(): void
    {
        $algorithm = new HmacSha256('test-secret-key');
        $sig1 = $algorithm->sign('test data');
        $sig2 = $algorithm->sign('test data');

        $this->assertSame($sig1, $sig2);
    }

    public function testVerifyAcceptsRawBytesAndReturnsTrueForValidSignature(): void
    {
        $algorithm = new HmacSha256('test-secret-key');
        $signature = $algorithm->sign('test data');

        $this->assertTrue($algorithm->verify('test data', $signature));
    }

    public function testVerifyReturnsFalseForInvalidSignature(): void
    {
        $algorithm = new HmacSha256('test-secret-key');
        $signature = $algorithm->sign('test data');

        $this->assertFalse($algorithm->verify('different data', $signature));
    }

    public function testVerifyReturnsFalseForTamperedSignature(): void
    {
        $algorithm = new HmacSha256('test-secret-key');
        $signature = $algorithm->sign('test data');

        $this->assertFalse($algorithm->verify('test data', $signature . 'x'));
    }

    public function testDifferentKeysProduceDifferentSignatures(): void
    {
        $alg1 = new HmacSha256('key-one');
        $alg2 = new HmacSha256('key-two');

        $sig1 = $alg1->sign('same data');
        $sig2 = $alg2->sign('same data');

        $this->assertNotSame($sig1, $sig2);
    }

    public function testGetAlgorithmIdReturnsHmacSha256(): void
    {
        $algorithm = new HmacSha256('key');
        $this->assertSame('hmac-sha256', $algorithm->getAlgorithmId());
    }

    public function testThrowsOnEmptySecretKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        new HmacSha256('');
    }
}
