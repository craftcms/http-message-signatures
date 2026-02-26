<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit;

use Bakame\Http\StructuredFields\Item;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use HttpMessageSignatures\ComponentDeriver;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ComponentDeriverTest extends TestCase
{
    private ComponentDeriver $deriver;

    private Request $request;

    protected function setUp(): void
    {
        $this->deriver = new ComponentDeriver();
        $this->request = new Request(
            'POST',
            'https://example.com:443/path?param=value&other=test',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/json',
                'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            ],
            '{"hello":"world"}',
        );
    }

    public function testMethodReturnsUppercaseMethod(): void
    {
        $this->assertSame('POST', $this->deriver->deriveComponent(Item::fromString('@method'), $this->request));
    }

    public function testPathReturnsTheRequestPath(): void
    {
        $this->assertSame('/path', $this->deriver->deriveComponent(Item::fromString('@path'), $this->request));
    }

    public function testPathReturnsSlashForEmptyPath(): void
    {
        $request = new Request('GET', 'https://example.com');
        $this->assertSame('/', $this->deriver->deriveComponent(Item::fromString('@path'), $request));
    }

    public function testQueryReturnsQuestionMarkPrefixWithQueryString(): void
    {
        $this->assertSame('?param=value&other=test', $this->deriver->deriveComponent(
            Item::fromString('@query'),
            $this->request,
        ));
    }

    public function testQueryReturnsQuestionMarkForEmptyQuery(): void
    {
        $request = new Request('GET', 'https://example.com/path');
        $this->assertSame('?', $this->deriver->deriveComponent(Item::fromString('@query'), $request));
    }

    public function testAuthorityReturnsLowercaseHost(): void
    {
        $this->assertSame('example.com', $this->deriver->deriveComponent(
            Item::fromString('@authority'),
            $this->request,
        ));
    }

    public function testAuthorityIncludesNonDefaultPort(): void
    {
        $request = new Request('GET', 'https://example.com:8443/path');
        $this->assertSame('example.com:8443', $this->deriver->deriveComponent(
            Item::fromString('@authority'),
            $request,
        ));
    }

    public function testSchemeReturnsLowercaseScheme(): void
    {
        $this->assertSame('https', $this->deriver->deriveComponent(Item::fromString('@scheme'), $this->request));
    }

    public function testTargetUriReturnsFullUri(): void
    {
        $request = new Request('GET', 'https://example.com/path?query=value');
        $this->assertSame('https://example.com/path?query=value', $this->deriver->deriveComponent(
            Item::fromString('@target-uri'),
            $request,
        ));
    }

    public function testRequestTargetReturnsRequestTarget(): void
    {
        $this->assertSame('/path?param=value&other=test', $this->deriver->deriveComponent(
            Item::fromString('@request-target'),
            $this->request,
        ));
    }

    public function testStatusReturnsResponseStatusCode(): void
    {
        $this->assertSame('200', $this->deriver->deriveComponent(Item::fromString('@status'), new Response(200)));
    }

    public function testStatusThrowsForNonResponse(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->deriver->deriveComponent(Item::fromString('@status'), $this->request);
    }

    public function testQueryParamExtractsNamedQueryParameter(): void
    {
        $component = Item::fromHttpValue('"@query-param";name="param"');
        $this->assertSame('value', $this->deriver->deriveComponent($component, $this->request));
    }

    public function testQueryParamThrowsWhenParameterIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $component = Item::fromHttpValue('"@query-param";name="nonexistent"');
        $this->deriver->deriveComponent($component, $this->request);
    }

    public function testHeaderComponentReturnsHeaderValue(): void
    {
        $this->assertSame('application/json', $this->deriver->deriveComponent(
            Item::fromString('content-type'),
            $this->request,
        ));
    }

    public function testHeaderComponentThrowsWhenHeaderNotFound(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->deriver->deriveComponent(Item::fromString('x-nonexistent'), $this->request);
    }

    public function testHeaderComponentCombinesMultipleValuesWithComma(): void
    {
        $request = new Request('GET', 'https://example.com', ['Accept' => ['text/html', 'application/json']]);
        $this->assertSame('text/html, application/json', $this->deriver->deriveComponent(
            Item::fromString('accept'),
            $request,
        ));
    }

    public function testDerivedComponentsWorkForResponsesWithOriginalRequest(): void
    {
        $request = new Request('GET', 'https://example.com/path');
        $response = new Response(200);

        $this->assertSame('GET', $this->deriver->deriveComponent(Item::fromString('@method'), $response, $request));
    }

    public function testDerivedComponentsThrowForResponseWithoutOriginalRequest(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->deriver->deriveComponent(Item::fromString('@method'), new Response(200));
    }
}
