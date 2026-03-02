<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit\Url;

use Http\Factory\Guzzle\RequestFactory;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\SignatureException;
use HttpMessageSignatures\Url\UrlSigner;
use HttpMessageSignatures\Url\UrlSigningConfig;
use PHPUnit\Framework\TestCase;

final class UrlSignerTest extends TestCase
{
    private UrlSigner $signer;

    private RequestFactory $requestFactory;

    protected function setUp(): void
    {
        $this->requestFactory = new RequestFactory();
        $this->signer = new UrlSigner(new HmacSha256('test-secret-key'), $this->requestFactory);
    }

    public function test_sign_appends_signature_params(): void
    {
        $signed = $this->signer->sign('https://example.com/path');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('signature', $params);
        $this->assertArrayHasKey('signature-input', $params);
    }

    public function test_sign_preserves_existing_query_params(): void
    {
        $signed = $this->signer->sign('https://example.com/path?foo=bar&baz=qux');
        $params = $this->extractQueryParams($signed);

        $this->assertSame('bar', $params['foo']);
        $this->assertSame('qux', $params['baz']);
        $this->assertArrayHasKey('signature', $params);
    }

    public function test_sign_strips_existing_signature_params(): void
    {
        $signed = $this->signer->sign('https://example.com/path?signature=old&signature-input=old&keep=1');
        $params = $this->extractQueryParams($signed);

        $this->assertSame('1', $params['keep']);
        $this->assertNotSame('old', $params['signature']);
    }

    public function test_sign_preserves_fragment(): void
    {
        $signed = $this->signer->sign('https://example.com/path#section');

        $this->assertStringContainsString('#section', $signed);
    }

    public function test_sign_includes_signature_input_with_components(): void
    {
        $signed = $this->signer->sign('https://example.com/path');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('signature-input', $params);
        $this->assertStringContainsString('@target-uri', $params['signature-input']);
    }

    public function test_sign_with_custom_config(): void
    {
        $config = new UrlSigningConfig(
            components: ['@path', '@query'],
            signatureParam: 'sig',
            signatureInputParam: 'sig-input',
            tag: 'custom-tag',
        );

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), new RequestFactory(), $config);

        $signed = $signer->sign('https://example.com/path?foo=bar');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('sig', $params);
        $this->assertArrayHasKey('sig-input', $params);
        $this->assertArrayNotHasKey('signature', $params);
    }

    public function test_sign_with_expiration(): void
    {
        $config = new UrlSigningConfig(created: 1000000, expiresAfter: 3600);

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), new RequestFactory(), $config);

        $signed = $signer->sign('https://example.com/path');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('signature-input', $params);
        $this->assertStringContainsString('expires=1003600', $params['signature-input']);
        $this->assertStringContainsString('created=1000000', $params['signature-input']);
    }

    public function test_sign_throws_on_empty_components(): void
    {
        $config = new UrlSigningConfig(components: []);

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), new RequestFactory(), $config);

        $this->expectException(SignatureException::class);
        $signer->sign('https://example.com/path');
    }

    public function test_sign_produces_deterministic_output(): void
    {
        $config = new UrlSigningConfig(created: 1000000);

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), new RequestFactory(), $config);

        $url = 'https://example.com/path?foo=bar';
        $signed1 = $signer->sign($url);
        $signed2 = $signer->sign($url);

        $this->assertSame($signed1, $signed2);
    }

    public function test_sign_with_created_null_omits_created(): void
    {
        $config = new UrlSigningConfig(created: null);

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/path');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('signature-input', $params);
        $this->assertStringNotContainsString('created=', $params['signature-input']);
    }

    public function test_sign_accepts_request_interface(): void
    {
        $config = new UrlSigningConfig(created: 1000000);
        $signer = new UrlSigner(new HmacSha256('test-secret-key'), $this->requestFactory, $config);

        $request = $this->requestFactory->createRequest('POST', 'https://example.com/form');
        $signed = $signer->sign($request);

        $params = $this->extractQueryParams($signed);
        $this->assertArrayHasKey('signature', $params);
        $this->assertStringStartsWith('https://example.com/form?', $signed);
    }

    public function test_sign_request_preserves_method_in_signature(): void
    {
        $config = new UrlSigningConfig(components: ['@method', '@target-uri'], created: 1000000);
        $algorithm = new HmacSha256('test-secret-key');

        $signer = new UrlSigner($algorithm, $this->requestFactory, $config);

        // Sign the same URL with different methods — signatures should differ
        $getRequest = $this->requestFactory->createRequest('GET', 'https://example.com/form');
        $postRequest = $this->requestFactory->createRequest('POST', 'https://example.com/form');

        $signedGet = $signer->sign($getRequest);
        $signedPost = $signer->sign($postRequest);

        $getParams = $this->extractQueryParams($signedGet);
        $postParams = $this->extractQueryParams($signedPost);

        $this->assertNotSame($getParams['signature'], $postParams['signature']);
    }

    public function test_with_current_time_factory(): void
    {
        $before = time();
        $config = UrlSigningConfig::withCurrentTime(expiresAfter: 3600);
        $after = time();

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), $this->requestFactory, $config);

        $signed = $signer->sign('https://example.com/path');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('signature-input', $params);
        $this->assertStringContainsString('created=', $params['signature-input']);
        $this->assertStringContainsString('expires=', $params['signature-input']);

        // Verify the created timestamp is within the expected range
        $this->assertGreaterThanOrEqual($before, $config->created);
        $this->assertLessThanOrEqual($after, $config->created);
    }

    /**
     * Extract query parameters from a URL string.
     *
     * @return array<string, string>
     */
    private function extractQueryParams(string $url): array
    {
        return \League\Uri\Components\Query::fromUri($url)->parameters();
    }
}
