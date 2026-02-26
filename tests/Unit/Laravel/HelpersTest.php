<?php

declare(strict_types=1);

use function HttpMessageSignatures\Laravel\sign_http_message;
use function HttpMessageSignatures\Laravel\sign_request;
use function HttpMessageSignatures\Laravel\verify_http_message;
use GuzzleHttp\Psr7\Request;
use Illuminate\Http\Request as LaravelRequest;

test('sign_http_message helper signs a message', function () {
    // This test requires Laravel to be available
    if (!class_exists(\Illuminate\Support\Facades\App::class)) {
        $this->markTestSkipped('Laravel is not available');
    }

    $request = new Request('POST', 'https://example.com/path', [
        'Content-Type' => 'application/json',
    ]);

    // Note: This test requires proper Laravel setup with configured algorithm
    // In a real scenario, you'd mock the App facade or set up a test environment
    expect(fn() => sign_http_message($request, ['@method', '@path'], ['keyid' => 'test-key']))
        ->not->toThrow();
})->skip(fn() => !class_exists(\Illuminate\Support\Facades\App::class), 'Laravel is not available');

test('verify_http_message helper verifies a message', function () {
    // This test requires Laravel to be available
    if (!class_exists(\Illuminate\Support\Facades\App::class)) {
        $this->markTestSkipped('Laravel is not available');
    }

    $request = new Request('POST', 'https://example.com/path');

    // Note: This test requires proper Laravel setup with configured algorithm
    expect(fn() => verify_http_message($request))->not->toThrow();
})->skip(fn() => !class_exists(\Illuminate\Support\Facades\App::class), 'Laravel is not available');

test('sign_request helper signs a Laravel request', function () {
    // This test requires Laravel to be available
    if (!class_exists(LaravelRequest::class)) {
        $this->markTestSkipped('Laravel is not available');
    }

    $request = LaravelRequest::create('https://example.com/path', 'POST');

    // Note: This test requires proper Laravel setup with configured algorithm
    expect(fn() => sign_request($request, ['@method', '@path'], ['keyid' => 'test-key']))
        ->not->toThrow();
})->skip(fn() => !class_exists(LaravelRequest::class), 'Laravel is not available');
