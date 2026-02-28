<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit;

use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\VerificationException;
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Verifier;
use PHPUnit\Framework\TestCase;

final class VerifierTest extends TestCase
{
    private Signer $signer;

    private Verifier $verifier;

    private Request $request;

    protected function setUp(): void
    {
        $algorithm = new HmacSha256('test-secret-key-for-verification');
        $this->signer = new Signer($algorithm);
        $this->verifier = new Verifier($algorithm);
        $this->request = new Request(
            'POST',
            'https://example.com/foo?bar=baz',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/json',
                'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            ],
            '{"hello":"world"}',
        );
    }

    public function testVerifyReturnsTrueForAValidlySignedMessage(): void
    {
        $signed = $this->signer->sign(
            $this->request,
            ['@method', '@path', 'content-type'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $this->assertTrue($this->verifier->verify($signed));
    }

    public function testVerifyWithSpecificSignatureId(): void
    {
        $signed = $this->signer->sign(
            $this->request,
            ['@method', '@path'],
            ['signatureId' => 'my-sig', 'created' => 1618884473],
        );

        $this->assertTrue($this->verifier->verify($signed, 'my-sig'));
    }

    public function testVerifyThrowsForUnknownSignatureId(): void
    {
        $this->expectException(VerificationException::class);

        $signed = $this->signer->sign($this->request, ['@method'], ['created' => 1618884473]);

        $this->verifier->verify($signed, 'nonexistent');
    }

    public function testVerifyThrowsForTamperedMessage(): void
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Signature verification failed');

        $signed = $this->signer->sign(
            $this->request,
            ['@method', '@path', 'content-type'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $tampered = $signed->withHeader('Content-Type', 'text/plain');
        $this->verifier->verify($tampered);
    }

    public function testVerifyThrowsWhenSignatureInputHeaderIsMissing(): void
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Signature-Input header not found');

        $this->verifier->verify($this->request);
    }

    public function testVerifyThrowsWhenSignatureHeaderIsMissing(): void
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Signature header not found');

        $request = $this->request->withHeader('Signature-Input', 'sig1=(@method);created=1618884473');
        $this->verifier->verify($request);
    }

    public function testVerifyThrowsForWrongKey(): void
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Signature verification failed');

        $signed = $this->signer->sign($this->request, ['@method'], ['created' => 1618884473]);

        $wrongVerifier = new Verifier(new HmacSha256('wrong-key'));
        $wrongVerifier->verify($signed);
    }

    public function testVerifyChecksExpiration(): void
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Signature has expired');

        $signed = $this->signer->sign($this->request, ['@method'], ['created' => 1000000000, 'expires' => 1000000001]);

        $this->verifier->verify($signed);
    }

    public function testRoundTripSignAndVerifyWithMultipleComponents(): void
    {
        $signed = $this->signer->sign(
            $this->request,
            ['@method', '@path', '@query', '@authority', 'content-type', 'date'],
            ['keyid' => 'test-key', 'created' => 1618884473, 'nonce' => 'abc123'],
        );

        $this->assertTrue($this->verifier->verify($signed));
    }
}
