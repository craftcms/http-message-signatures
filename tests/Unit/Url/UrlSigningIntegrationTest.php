<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit\Url;

use Http\Factory\Guzzle\RequestFactory;
use HttpMessageSignatures\Algorithm\Ed25519;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Algorithm\RsaSha256;
use HttpMessageSignatures\Exception\VerificationException;
use HttpMessageSignatures\Url\UrlSigner;
use HttpMessageSignatures\Url\UrlSigningConfig;
use HttpMessageSignatures\Url\UrlVerifier;
use PHPUnit\Framework\TestCase;

final class UrlSigningIntegrationTest extends TestCase
{
    private RequestFactory $requestFactory;

    protected function setUp(): void
    {
        $this->requestFactory = new RequestFactory();
    }

    public function test_round_trip_with_hmac_sha256(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $algorithm = new HmacSha256('shared-secret-key');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/files/report.pdf?user=42');

        $this->assertTrue($verifier->verify($signed));
    }

    public function test_round_trip_with_rsa_sha256(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($resource);
        openssl_pkey_export($resource, $privateKeyPem);
        $details = openssl_pkey_get_details($resource);
        $this->assertIsArray($details);

        $algorithm = new RsaSha256($privateKeyPem, $details['key']);

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/files/report.pdf');

        $this->assertTrue($verifier->verify($signed));
    }

    public function test_round_trip_with_ed25519(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $keypair = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        $algorithm = new Ed25519($secretKey, $publicKey);

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/download?file=data.csv');

        $this->assertTrue($verifier->verify($signed));
    }

    public function test_tampered_path_fails_verification(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/allowed-file.pdf');
        $tampered = str_replace('/allowed-file.pdf', '/secret-file.pdf', $signed);

        $this->expectException(VerificationException::class);
        $verifier->verify($tampered);
    }

    public function test_tampered_query_fails_verification(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/api?role=user');
        $tampered = str_replace('role=user', 'role=admin', $signed);

        $this->expectException(VerificationException::class);
        $verifier->verify($tampered);
    }

    public function test_tampered_host_fails_verification(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://trusted.com/resource');
        $tampered = str_replace('trusted.com', 'evil.com', $signed);

        $this->expectException(VerificationException::class);
        $verifier->verify($tampered);
    }

    public function test_expiration_with_future_timestamp(): void
    {
        $config = new UrlSigningConfig(created: time(), expiresAfter: 3600);

        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/path');

        $this->assertTrue($verifier->verify($signed));
    }

    public function test_expired_url_fails_verification(): void
    {
        // Created far in the past with very short expiry — already expired
        $config = new UrlSigningConfig(created: 1000000, expiresAfter: 1);

        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/path');

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('expired');
        $verifier->verify($signed);
    }

    public function test_round_trip_with_multiple_components(): void
    {
        $config = new UrlSigningConfig(components: ['@scheme', '@authority', '@path', '@query'], created: 1000000);

        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/api/v1/data?format=json&page=2');

        $this->assertTrue($verifier->verify($signed));
    }

    public function test_round_trip_with_url_without_query(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/simple-path');

        $this->assertTrue($verifier->verify($signed));
    }

    public function test_round_trip_with_special_characters_in_query(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $algorithm = new HmacSha256('secret');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/search?q=hello%20world&lang=en');

        $this->assertTrue($verifier->verify($signed));
    }
}
