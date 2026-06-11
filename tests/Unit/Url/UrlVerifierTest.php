<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit\Url;

use Http\Factory\Guzzle\RequestFactory;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\VerificationException;
use HttpMessageSignatures\Url\UrlSigner;
use HttpMessageSignatures\Url\UrlSigningConfig;
use HttpMessageSignatures\Url\UrlVerifier;
use PHPUnit\Framework\TestCase;

final class UrlVerifierTest extends TestCase
{
    private UrlSigner $signer;

    private UrlVerifier $verifier;

    private RequestFactory $requestFactory;

    protected function setUp(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $algorithm = new HmacSha256('test-secret-key');
        $this->requestFactory = new RequestFactory();

        $this->signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $this->verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);
    }

    public function test_verify_valid_signed_url(): void
    {
        $signed = $this->signer->sign('https://example.com/path');

        $this->assertTrue($this->verifier->verify($signed));
    }

    public function test_verify_valid_signed_url_with_query_params(): void
    {
        $signed = $this->signer->sign('https://example.com/path?foo=bar&baz=qux');

        $this->assertTrue($this->verifier->verify($signed));
    }

    public function test_verify_throws_when_signature_missing(): void
    {
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Signature parameter');

        $this->verifier->verify('https://example.com/path');
    }

    public function test_verify_uses_configured_components_without_signature_input_param(): void
    {
        $config = new UrlSigningConfig(components: ['@path'], created: 1000000);
        $algorithm = new HmacSha256('test-secret-key');
        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/path?foo=bar');
        $tampered = str_replace('foo=bar', 'foo=baz', $signed);

        $this->assertTrue($verifier->verify($tampered));
    }

    public function test_verify_strips_signature_input_param(): void
    {
        $signed = $this->signer->sign('https://example.com/path?foo=bar');
        $withSignatureInput = $signed . '&signature-input=legacy';

        $this->assertTrue($this->verifier->verify($withSignatureInput));
    }

    public function test_verify_throws_on_tampered_path(): void
    {
        $signed = $this->signer->sign('https://example.com/original');
        $tampered = str_replace('/original', '/tampered', $signed);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('verification failed');

        $this->verifier->verify($tampered);
    }

    public function test_verify_throws_on_tampered_query(): void
    {
        $signed = $this->signer->sign('https://example.com/path?token=valid');
        $tampered = str_replace('token=valid', 'token=evil', $signed);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('verification failed');

        $this->verifier->verify($tampered);
    }

    public function test_verify_throws_on_tampered_host(): void
    {
        $signed = $this->signer->sign('https://example.com/path');
        $tampered = str_replace('example.com', 'evil.com', $signed);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('verification failed');

        $this->verifier->verify($tampered);
    }

    public function test_verify_throws_on_wrong_key(): void
    {
        $signed = $this->signer->sign('https://example.com/path');

        $wrongVerifier = new UrlVerifier(
            new HmacSha256('wrong-secret-key'),
            new RequestFactory(),
            new UrlSigningConfig(created: 1000000),
        );

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('verification failed');

        $wrongVerifier->verify($signed);
    }

    public function test_verify_throws_on_signature_with_invalid_base64url_alphabet(): void
    {
        $signed = $this->signer->sign('https://example.com/path');
        $tampered = preg_replace('/([?&]signature=)[^&]*/', '$1abcd/', $signed);

        $this->assertNotNull($tampered);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('Invalid base64url data');

        $this->verifier->verify($tampered);
    }

    public function test_verify_throws_on_expired_signature(): void
    {
        $config = new UrlSigningConfig(created: 1000000, expiresAfter: 1); // 1 second — already expired relative to timestamp 1000000

        $algorithm = new HmacSha256('test-secret-key');
        $requestFactory = new RequestFactory();

        $signer = new UrlSigner($algorithm, $requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $requestFactory, $config);

        $signed = $signer->sign('https://example.com/path');

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('expired');

        $verifier->verify($signed);
    }

    public function test_verify_with_custom_param_names(): void
    {
        $config = new UrlSigningConfig(signatureParam: 'sig', created: 1000000);

        $algorithm = new HmacSha256('test-secret-key');
        $requestFactory = new RequestFactory();

        $signer = new UrlSigner($algorithm, $requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $requestFactory, $config);

        $signed = $signer->sign('https://example.com/path');

        $this->assertTrue($verifier->verify($signed));
    }

    public function test_verify_round_trip_with_post_request(): void
    {
        $config = new UrlSigningConfig(components: ['@method', '@target-uri'], created: 1000000);
        $algorithm = new HmacSha256('test-secret-key');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        $postRequest = $this->requestFactory->createRequest('POST', 'https://example.com/form');
        $signed = $signer->sign($postRequest);

        // Verify with POST request — should pass
        $verifyRequest = $this->requestFactory->createRequest('POST', $signed);
        $this->assertTrue($verifier->verify($verifyRequest));
    }

    public function test_verify_fails_when_method_mismatch(): void
    {
        $config = new UrlSigningConfig(components: ['@method', '@target-uri'], created: 1000000);
        $algorithm = new HmacSha256('test-secret-key');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);
        $verifier = new UrlVerifier($algorithm, $this->requestFactory, $config);

        // Sign as POST
        $postRequest = $this->requestFactory->createRequest('POST', 'https://example.com/form');
        $signed = $signer->sign($postRequest);

        // Verify as GET — should fail because @method is covered
        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('verification failed');

        $verifier->verify($signed); // string defaults to GET
    }
}
