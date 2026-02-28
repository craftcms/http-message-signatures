<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit\Url;

use HttpMessageSignatures\Url\UrlQueryHelper;
use PHPUnit\Framework\TestCase;
use Uri\Rfc3986\Uri;

final class UrlQueryHelperTest extends TestCase
{
    public function test_strip_params_removes_named_params(): void
    {
        $uri = new Uri('https://example.com/path?foo=1&bar=2&baz=3');
        $result = UrlQueryHelper::stripParams($uri, ['bar']);

        $this->assertSame('https://example.com/path?foo=1&baz=3', $result->toString());
    }

    public function test_strip_params_removes_multiple_params(): void
    {
        $uri = new Uri('https://example.com/path?foo=1&bar=2&baz=3');
        $result = UrlQueryHelper::stripParams($uri, ['foo', 'baz']);

        $this->assertSame('https://example.com/path?bar=2', $result->toString());
    }

    public function test_strip_params_handles_no_query_string(): void
    {
        $uri = new Uri('https://example.com/path');
        $result = UrlQueryHelper::stripParams($uri, ['foo']);

        $this->assertSame('https://example.com/path', $result->toString());
    }

    public function test_strip_params_removes_all_params(): void
    {
        $uri = new Uri('https://example.com/path?foo=1');
        $result = UrlQueryHelper::stripParams($uri, ['foo']);

        $this->assertNull($result->getQuery());
    }

    public function test_strip_params_preserves_unmatched(): void
    {
        $uri = new Uri('https://example.com/path?foo=1&bar=2');
        $result = UrlQueryHelper::stripParams($uri, ['nonexistent']);

        $this->assertSame('https://example.com/path?foo=1&bar=2', $result->toString());
    }

    public function test_append_params_adds_to_existing_query(): void
    {
        $uri = new Uri('https://example.com/path?existing=1');
        $result = UrlQueryHelper::appendParams($uri, ['new' => 'value']);

        $this->assertSame('https://example.com/path?existing=1&new=value', $result);
    }

    public function test_append_params_starts_new_query(): void
    {
        $uri = new Uri('https://example.com/path');
        $result = UrlQueryHelper::appendParams($uri, ['key' => 'value']);

        $this->assertSame('https://example.com/path?key=value', $result);
    }

    public function test_append_params_url_encodes_values(): void
    {
        $uri = new Uri('https://example.com/path');
        $result = UrlQueryHelper::appendParams($uri, ['data' => 'hello world&more']);

        $this->assertStringContainsString('data=hello%20world%26more', $result);
    }

    public function test_append_params_preserves_fragment(): void
    {
        $uri = new Uri('https://example.com/path#section');
        $result = UrlQueryHelper::appendParams($uri, ['key' => 'value']);

        $this->assertSame('https://example.com/path?key=value#section', $result);
    }

    public function test_extract_param_finds_value(): void
    {
        $uri = new Uri('https://example.com/path?foo=bar&baz=qux');

        $this->assertSame('bar', UrlQueryHelper::extractParam($uri, 'foo'));
        $this->assertSame('qux', UrlQueryHelper::extractParam($uri, 'baz'));
    }

    public function test_extract_param_returns_null_when_missing(): void
    {
        $uri = new Uri('https://example.com/path?foo=bar');

        $this->assertNull(UrlQueryHelper::extractParam($uri, 'nonexistent'));
    }

    public function test_extract_param_returns_null_for_no_query(): void
    {
        $uri = new Uri('https://example.com/path');

        $this->assertNull(UrlQueryHelper::extractParam($uri, 'foo'));
    }

    public function test_extract_param_handles_url_encoded_value(): void
    {
        $uri = new Uri('https://example.com/path?data=hello%20world');

        $this->assertSame('hello world', UrlQueryHelper::extractParam($uri, 'data'));
    }

    public function test_base64url_encode_decode_round_trip(): void
    {
        $data = random_bytes(32);
        $encoded = UrlQueryHelper::base64urlEncode($data);
        $decoded = UrlQueryHelper::base64urlDecode($encoded);

        $this->assertSame($data, $decoded);
    }

    public function test_base64url_encode_produces_url_safe_chars(): void
    {
        // Use data known to produce + and / in standard base64
        $data = base64_decode('+/+/+/==');
        $encoded = UrlQueryHelper::base64urlEncode($data);

        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    public function test_base64url_decode_throws_on_invalid_data(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        UrlQueryHelper::base64urlDecode('not valid base64!!!');
    }
}
