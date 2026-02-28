<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Tests\Unit;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\Parameters;
use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\SignatureBase;
use PHPUnit\Framework\TestCase;

final class SignatureBaseTest extends TestCase
{
    public function testBuildsSignatureBaseStringWithDerivedComponents(): void
    {
        $signatureBase = new SignatureBase();

        $request = new Request('POST', 'https://example.com/foo?param=value&pet=dog', [
            'Host' => 'example.com',
            'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            'Content-Type' => 'application/json',
        ]);

        $components = [
            Item::fromString('@method'),
            Item::fromString('@authority'),
            Item::fromString('@path'),
            Item::fromString('content-type'),
        ];

        $params = Parameters::fromAssociative([
            'created' => 1618884473,
            'keyid' => 'test-key-rsa-pss',
        ]);

        $result = $signatureBase->build(InnerList::fromAssociative($components, $params), $request);
        $lines = explode("\n", $result);

        $this->assertSame('"@method": POST', $lines[0]);
        $this->assertSame('"@authority": example.com', $lines[1]);
        $this->assertSame('"@path": /foo', $lines[2]);
        $this->assertSame('"content-type": application/json', $lines[3]);
        $this->assertStringStartsWith('"@signature-params": ', $lines[4]);
        $this->assertStringContainsString('("@method" "@authority" "@path" "content-type")', $lines[4]);
        $this->assertStringContainsString(';created=1618884473', $lines[4]);
        $this->assertStringContainsString(';keyid="test-key-rsa-pss"', $lines[4]);
    }

    public function testSignatureBaseEndsWithSignatureParamsLine(): void
    {
        $signatureBase = new SignatureBase();
        $request = new Request('GET', 'https://example.com/');

        $signatureInput = InnerList::fromAssociative([Item::fromString('@method')], Parameters::fromAssociative([
            'created' => 1618884473,
        ]));

        $result = $signatureBase->build($signatureInput, $request);
        $lines = explode("\n", $result);

        $this->assertStringStartsWith('"@signature-params": ', (string) end($lines));
    }

    public function testSignatureBaseHandlesQueryWithQuestionMarkPrefix(): void
    {
        $signatureBase = new SignatureBase();
        $request = new Request('GET', 'https://example.com/path?foo=bar');

        $signatureInput = InnerList::fromAssociative([Item::fromString('@query')], Parameters::fromAssociative([
            'created' => 1618884473,
        ]));

        $result = $signatureBase->build($signatureInput, $request);
        $lines = explode("\n", $result);

        $this->assertSame('"@query": ?foo=bar', $lines[0]);
    }
}
