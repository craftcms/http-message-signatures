<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\SignatureException;
use HttpMessageSignatures\Signer;

beforeEach(function () {
    $this->algorithm = new HmacSha256('secret-key');
    $this->signer = new Signer($this->algorithm);
    $this->request = new Request('POST', 'https://example.com/path', [
        'Content-Type' => 'application/json',
        'Date' => 'Mon, 01 Jan 2024 12:00:00 GMT',
    ], '{"data":"value"}');
});

test('signs a request with signature headers', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path', '@authority', 'content-type'],
        ['keyid' => 'test-key']
    );
    
    expect($signed->hasHeader('Signature-Input'))->toBeTrue()
        ->and($signed->hasHeader('Signature'))->toBeTrue();
});

test('throws exception when keyid is missing', function () {
    expect(fn() => $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        []
    ))->toThrow(SignatureException::class, 'keyid is required');
});

test('throws exception when components are empty', function () {
    expect(fn() => $this->signer->sign(
        $this->request,
        [],
        ['keyid' => 'test-key']
    ))->toThrow(SignatureException::class, 'At least one component must be specified');
});

test('includes created timestamp by default', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        ['keyid' => 'test-key']
    );
    
    $signatureInput = $signed->getHeaderLine('Signature-Input');
    
    expect($signatureInput)->toContain('created=');
});

test('includes expires when provided', function () {
    $expires = time() + 300;
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        [
            'keyid' => 'test-key',
            'expires' => $expires,
        ]
    );
    
    $signatureInput = $signed->getHeaderLine('Signature-Input');
    
    expect($signatureInput)->toContain('expires=');
});

test('includes nonce when provided', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        [
            'keyid' => 'test-key',
            'nonce' => 'random-nonce',
        ]
    );
    
    $signatureInput = $signed->getHeaderLine('Signature-Input');
    
    expect($signatureInput)->toContain('nonce=');
});

test('uses custom signature ID', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        [
            'keyid' => 'test-key',
            'signatureId' => 'custom-sig',
        ]
    );
    
    $signatureInput = $signed->getHeaderLine('Signature-Input');
    
    expect($signatureInput)->toContain('custom-sig=');
});

test('returns new immutable request instance', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        ['keyid' => 'test-key']
    );
    
    expect($signed)->not->toBe($this->request)
        ->and($this->request->hasHeader('Signature-Input'))->toBeFalse();
});

test('appends to existing signature headers', function () {
    $request = $this->request->withHeader('Signature-Input', 'existing=("header");created=1234567890');
    
    $signed = $this->signer->sign(
        $request,
        ['@method', '@path'],
        ['keyid' => 'test-key']
    );
    
    $signatureInput = $signed->getHeaderLine('Signature-Input');
    
    expect($signatureInput)->toContain('existing=')
        ->and($signatureInput)->toContain('sig1=');
});

