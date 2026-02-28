<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests;

use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\Algorithm\Ed25519;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Algorithm\RsaSha256;
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Verifier;
use PHPUnit\Framework\TestCase;

final class IntegrationTest extends TestCase
{
    public function testRoundTripWithHmacSha256(): void
    {
        $algorithm = new HmacSha256('a-shared-secret-key');
        $signer = new Signer($algorithm);
        $verifier = new Verifier($algorithm);

        $signed = $signer->sign(
            $this->createRequest(),
            ['@method', '@path', '@authority', 'content-type'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $this->assertTrue($verifier->verify($signed));
    }

    public function testRoundTripWithRsaSha256(): void
    {
        $config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $resource = openssl_pkey_new($config);
        $this->assertNotFalse($resource);
        openssl_pkey_export($resource, $privateKeyPem);
        $details = openssl_pkey_get_details($resource);
        $this->assertIsArray($details);

        $signerAlg = new RsaSha256($privateKeyPem);
        $verifierAlg = new RsaSha256($privateKeyPem, $details['key']);

        $signer = new Signer($signerAlg);
        $verifier = new Verifier($verifierAlg);

        $signed = $signer->sign(
            $this->createRequest(),
            ['@method', '@path', '@authority', 'content-type'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $this->assertTrue($verifier->verify($signed));
    }

    public function testRoundTripWithEd25519(): void
    {
        $keypair = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        $signerAlg = new Ed25519($secretKey, $publicKey);
        $verifierAlg = new Ed25519($secretKey, $publicKey);

        $signer = new Signer($signerAlg);
        $verifier = new Verifier($verifierAlg);

        $signed = $signer->sign(
            $this->createRequest(),
            ['@method', '@path', '@authority', 'content-type'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $this->assertTrue($verifier->verify($signed));
    }

    public function testRoundTripWithQueryParamComponent(): void
    {
        $algorithm = new HmacSha256('secret');
        $signer = new Signer($algorithm);
        $verifier = new Verifier($algorithm);

        $signed = $signer->sign(
            $this->createRequest(),
            ['@method', '@query-param;name="param"'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $this->assertTrue($verifier->verify($signed));
    }

    public function testRoundTripWithQueryComponent(): void
    {
        $algorithm = new HmacSha256('secret');
        $signer = new Signer($algorithm);
        $verifier = new Verifier($algorithm);

        $signed = $signer->sign(
            $this->createRequest(),
            ['@method', '@query'],
            ['keyid' => 'test-key', 'created' => 1618884473],
        );

        $this->assertTrue($verifier->verify($signed));
    }

    private function createRequest(): Request
    {
        return new Request(
            'POST',
            'https://example.com/foo?param=value',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/json',
                'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            ],
            '{"hello":"world"}',
        );
    }
}
