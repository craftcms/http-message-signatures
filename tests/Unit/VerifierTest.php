<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\VerificationException;
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\Verifier;

beforeEach(function () {
    $this->algorithm = new HmacSha256('secret-key');
    $this->signer = new Signer($this->algorithm);
    $this->verifier = new Verifier($this->algorithm);
    
    $this->request = new Request('POST', 'https://example.com/path', [
        'Content-Type' => 'application/json',
        'Date' => 'Mon, 01 Jan 2024 12:00:00 GMT',
    ], '{"data":"value"}');
});

test('verifies valid signature', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path', '@authority', 'content-type'],
        ['keyid' => 'test-key']
    );
    
    expect($this->verifier->verify($signed))->toBeTrue();
});

test('throws exception when signature headers are missing', function () {
    expect(fn() => $this->verifier->verify($this->request))
        ->toThrow(VerificationException::class, 'Signature-Input header not found');
});

test('throws exception when signature has expired', function () {
    $expires = time() - 100; // Expired 100 seconds ago
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        [
            'keyid' => 'test-key',
            'expires' => $expires,
        ]
    );
    
    expect(fn() => $this->verifier->verify($signed))
        ->toThrow(VerificationException::class, 'Signature has expired');
});

test('verifies signature with specific signature ID', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        [
            'keyid' => 'test-key',
            'signatureId' => 'custom-sig',
        ]
    );
    
    expect($this->verifier->verify($signed, 'custom-sig'))->toBeTrue();
});

test('throws exception for invalid signature', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        ['keyid' => 'test-key']
    );
    
    // Modify the signature to make it invalid
    $signatureHeader = $signed->getHeaderLine('Signature');
    $invalidSignature = str_replace('sig1=:', 'sig1=:invalid:', $signatureHeader);
    $signed = $signed->withHeader('Signature', $invalidSignature);
    
    expect(fn() => $this->verifier->verify($signed))
        ->toThrow(VerificationException::class, 'Signature verification failed');
});

test('throws exception for non-existent signature ID', function () {
    $signed = $this->signer->sign(
        $this->request,
        ['@method', '@path'],
        ['keyid' => 'test-key']
    );
    
    expect(fn() => $this->verifier->verify($signed, 'non-existent'))
        ->toThrow(VerificationException::class, "Signature input 'non-existent' not found");
});

