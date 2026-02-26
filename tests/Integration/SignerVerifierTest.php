<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Verifier;

test('full signing and verification flow with HMAC-SHA256', function () {
    $algorithm = new HmacSha256('secret-key');
    $signer = new Signer($algorithm);
    $verifier = new Verifier($algorithm);
    
    $request = new Request('POST', 'https://api.example.com/resource', [
        'Content-Type' => 'application/json',
        'Date' => 'Mon, 01 Jan 2024 12:00:00 GMT',
    ], '{"data":"value"}');
    
    $signed = $signer->sign(
        $request,
        ['@method', '@path', '@authority', 'content-type', 'date'],
        [
            'keyid' => 'my-key-id',
            'created' => time(),
            'expires' => time() + 300,
        ]
    );
    
    expect($verifier->verify($signed))->toBeTrue();
});

test('signing and verification with different components', function () {
    $algorithm = new HmacSha256('secret-key');
    $signer = new Signer($algorithm);
    $verifier = new Verifier($algorithm);
    
    $request = new Request('GET', 'https://example.com/path?foo=bar', [
        'Host' => 'example.com',
    ]);
    
    $signed = $signer->sign(
        $request,
        ['@method', '@path', '@query', '@authority'],
        ['keyid' => 'test-key']
    );
    
    expect($verifier->verify($signed))->toBeTrue();
});

test('signing and verification with query parameters', function () {
    $algorithm = new HmacSha256('secret-key');
    $signer = new Signer($algorithm);
    $verifier = new Verifier($algorithm);
    
    $request = new Request('GET', 'https://example.com/path?foo=bar&baz=qux');
    
    $signed = $signer->sign(
        $request,
        ['@method', '@path', '@query-param;name="foo"'],
        ['keyid' => 'test-key']
    );
    
    expect($verifier->verify($signed))->toBeTrue();
});

