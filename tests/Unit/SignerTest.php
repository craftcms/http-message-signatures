<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit;

use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\SignatureException;
use HttpMessageSignatures\Signer;
use PHPUnit\Framework\TestCase;

final class SignerTest extends TestCase
{
    private Signer $signer;

    private Request $request;

    protected function setUp(): void
    {
        $algorithm = new HmacSha256('test-secret-key-for-signing');
        $this->signer = new Signer($algorithm);
        $this->request = new Request(
            'POST',
            'https://example.com/foo',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/json',
                'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            ],
            '{"hello":"world"}',
        );
    }

    public function testSignAddsSignatureInputAndSignatureHeaders(): void
    {
        $signed = $this->signer->sign(
            $this->request,
            ['@method', '@path', 'content-type'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $this->assertTrue($signed->hasHeader('Signature-Input'));
        $this->assertTrue($signed->hasHeader('Signature'));
    }

    public function testSignatureInputContainsSignatureIdAndComponents(): void
    {
        $signed = $this->signer->sign(
            $this->request,
            ['@method', '@path', 'content-type'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $signatureInput = $signed->getHeaderLine('Signature-Input');

        $this->assertStringStartsWith('sig1=', $signatureInput);
        $this->assertStringContainsString('@method', $signatureInput);
        $this->assertStringContainsString('@path', $signatureInput);
        $this->assertStringContainsString('"content-type"', $signatureInput);
        $this->assertStringContainsString('keyid="test-key"', $signatureInput);
    }

    public function testSignatureHeaderContainsBase64EncodedBytes(): void
    {
        $signed = $this->signer->sign($this->request, ['@method'], ['created' => 1618884473]);

        $signature = $signed->getHeaderLine('Signature');

        $this->assertStringStartsWith('sig1=:', $signature);
        $this->assertStringEndsWith(':', $signature);
    }

    public function testCustomSignatureId(): void
    {
        $signed = $this->signer->sign(
            $this->request,
            ['@method'],
            ['signatureId' => 'custom-sig', 'created' => 1618884473],
        );

        $this->assertStringStartsWith('custom-sig=', $signed->getHeaderLine('Signature-Input'));
    }

    public function testOriginalRequestIsUnchanged(): void
    {
        $this->signer->sign($this->request, ['@method'], ['created' => 1618884473]);

        $this->assertFalse($this->request->hasHeader('Signature-Input'));
        $this->assertFalse($this->request->hasHeader('Signature'));
    }

    public function testThrowsWhenNoComponentsProvided(): void
    {
        $this->expectException(SignatureException::class);
        $this->signer->sign($this->request, []);
    }

    public function testIncludesAlgParameter(): void
    {
        $signed = $this->signer->sign($this->request, ['@method'], ['created' => 1618884473]);

        $this->assertStringContainsString('alg="hmac-sha256"', $signed->getHeaderLine('Signature-Input'));
    }

    public function testCreatedDefaultsToCurrentTime(): void
    {
        $signed = $this->signer->sign($this->request, ['@method']);
        $this->assertStringContainsString('created=', $signed->getHeaderLine('Signature-Input'));
    }

    public function testCreatedCanBeOmittedWithFalse(): void
    {
        $signed = $this->signer->sign($this->request, ['@method'], ['created' => false]);
        $this->assertStringNotContainsString('created=', $signed->getHeaderLine('Signature-Input'));
    }
}
