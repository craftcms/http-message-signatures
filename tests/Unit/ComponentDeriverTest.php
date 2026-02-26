<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\ComponentDeriver;

beforeEach(function () {
    $this->deriver = new ComponentDeriver();
});

test('derives @method component', function () {
    $request = new Request('POST', 'https://example.com/path');
    
    expect($this->deriver->deriveComponent('@method', $request))->toBe('POST');
});

test('derives @path component', function () {
    $request = new Request('GET', 'https://example.com/path/to/resource');
    
    expect($this->deriver->deriveComponent('@path', $request))->toBe('/path/to/resource');
});

test('derives @query component', function () {
    $request = new Request('GET', 'https://example.com/path?foo=bar&baz=qux');
    
    expect($this->deriver->deriveComponent('@query', $request))->toBe('foo=bar&baz=qux');
});

test('derives @authority component', function () {
    $request = new Request('GET', 'https://example.com:8080/path');
    
    expect($this->deriver->deriveComponent('@authority', $request))->toBe('example.com:8080');
});

test('derives @authority component without port for default ports', function () {
    $request = new Request('GET', 'https://example.com/path');
    
    expect($this->deriver->deriveComponent('@authority', $request))->toBe('example.com');
});

test('derives @scheme component', function () {
    $request = new Request('GET', 'https://example.com/path');
    
    expect($this->deriver->deriveComponent('@scheme', $request))->toBe('https');
});

test('derives @target-uri component', function () {
    $request = new Request('GET', 'https://example.com/path?foo=bar');
    
    expect($this->deriver->deriveComponent('@target-uri', $request))->toBe('https://example.com/path?foo=bar');
});

test('derives @request-target component', function () {
    $request = new Request('GET', 'https://example.com/path?foo=bar');
    
    $target = $this->deriver->deriveComponent('@request-target', $request);
    
    expect($target)->toBe('/path?foo=bar');
});

test('derives header component', function () {
    $request = new Request('GET', 'https://example.com/path', [
        'Content-Type' => 'application/json',
    ]);
    
    expect($this->deriver->deriveComponent('content-type', $request))->toBe('application/json');
});

test('derives header component with multiple values', function () {
    $request = new Request('GET', 'https://example.com/path', [
        'Accept' => ['text/html', 'application/json'],
    ]);
    
    expect($this->deriver->deriveComponent('accept', $request))->toBe('text/html, application/json');
});

test('derives empty string for missing header', function () {
    $request = new Request('GET', 'https://example.com/path');
    
    expect($this->deriver->deriveComponent('x-custom-header', $request))->toBe('');
});

test('derives @query-param component', function () {
    $request = new Request('GET', 'https://example.com/path?foo=bar&baz=qux');
    
    expect($this->deriver->deriveComponent('@query-param;name="foo"', $request))->toBe('bar');
});

test('derives empty string for missing query parameter', function () {
    $request = new Request('GET', 'https://example.com/path?foo=bar');
    
    expect($this->deriver->deriveComponent('@query-param;name="missing"', $request))->toBe('');
});

test('throws exception for invalid derived component', function () {
    $request = new Request('GET', 'https://example.com/path');
    
    expect(fn() => $this->deriver->deriveComponent('@invalid', $request))
        ->toThrow(InvalidArgumentException::class, 'Unknown derived component');
});

test('throws exception for derived component on non-request', function () {
    $response = new \GuzzleHttp\Psr7\Response(200);
    
    expect(fn() => $this->deriver->deriveComponent('@method', $response))
        ->toThrow(InvalidArgumentException::class, 'Derived components require a RequestInterface');
});

