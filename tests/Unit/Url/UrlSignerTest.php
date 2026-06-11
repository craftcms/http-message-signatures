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

    public function test_sign_appends_signature_param(): void
    {
        $signed = $this->signer->sign('https://example.com/path');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('signature', $params);
        $this->assertArrayNotHasKey('signature-input', $params);
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
        $signed = $this->signer->sign('https://example.com/path?signature=old&signature-input=keep&keep=1');
        $params = $this->extractQueryParams($signed);

        $this->assertSame('1', $params['keep']);
        $this->assertArrayNotHasKey('signature-input', $params);
        $this->assertNotSame('old', $params['signature']);
    }

    public function test_sign_preserves_fragment(): void
    {
        $signed = $this->signer->sign('https://example.com/path#section');

        $this->assertStringContainsString('#section', $signed);
    }

    public function test_sign_uses_configured_components(): void
    {
        $pathConfig = new UrlSigningConfig(components: ['@path'], created: 1000000);
        $queryConfig = new UrlSigningConfig(components: ['@path', '@query'], created: 1000000);

        $pathSigner = new UrlSigner(new HmacSha256('test-secret-key'), $this->requestFactory, $pathConfig);
        $querySigner = new UrlSigner(new HmacSha256('test-secret-key'), $this->requestFactory, $queryConfig);

        $pathParams = $this->extractQueryParams($pathSigner->sign('https://example.com/path?foo=bar'));
        $queryParams = $this->extractQueryParams($querySigner->sign('https://example.com/path?foo=bar'));

        $this->assertNotSame($pathParams['signature'], $queryParams['signature']);
    }

    public function test_sign_with_custom_config(): void
    {
        $config = new UrlSigningConfig(
            components: ['@path', '@query'],
            signatureParam: 'sig',
            tag: 'custom-tag',
        );

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), new RequestFactory(), $config);

        $signed = $signer->sign('https://example.com/path?foo=bar');
        $params = $this->extractQueryParams($signed);

        $this->assertArrayHasKey('sig', $params);
        $this->assertArrayNotHasKey('signature', $params);
        $this->assertArrayNotHasKey('signature-input', $params);
    }

    public function test_sign_with_expiration_affects_signature(): void
    {
        $config = new UrlSigningConfig(created: 1000000, expiresAfter: 3600);
        $configWithoutExpiration = new UrlSigningConfig(created: 1000000);

        $signer = new UrlSigner(new HmacSha256('test-secret-key'), new RequestFactory(), $config);
        $signerWithoutExpiration = new UrlSigner(new HmacSha256('test-secret-key'), new RequestFactory(), $configWithoutExpiration);

        $signed = $signer->sign('https://example.com/path');
        $signedWithoutExpiration = $signerWithoutExpiration->sign('https://example.com/path');
        $params = $this->extractQueryParams($signed);
        $paramsWithoutExpiration = $this->extractQueryParams($signedWithoutExpiration);

        $this->assertArrayHasKey('signature', $params);
        $this->assertArrayNotHasKey('signature-input', $params);
        $this->assertNotSame($paramsWithoutExpiration['signature'], $params['signature']);
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

        $this->assertArrayHasKey('signature', $params);
        $this->assertArrayNotHasKey('signature-input', $params);
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

        $this->assertArrayHasKey('signature', $params);
        $this->assertArrayNotHasKey('signature-input', $params);

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
