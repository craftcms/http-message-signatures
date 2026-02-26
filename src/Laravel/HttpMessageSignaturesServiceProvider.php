<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Laravel;

use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Algorithm\Ed25519;
use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Algorithm\RsaSha256;
use HttpMessageSignatures\ComponentDeriver;
use HttpMessageSignatures\Signer;
use HttpMessageSignatures\SignatureBaseStringBuilder;
use HttpMessageSignatures\StructuredFieldParser;
use HttpMessageSignatures\Verifier;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class HttpMessageSignaturesServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/http-message-signatures.php',
            'http-message-signatures'
        );

        $this->registerAlgorithm();
        $this->registerParser();
        $this->registerComponentDeriver();
        $this->registerBaseStringBuilder();
        $this->registerSigner();
        $this->registerVerifier();
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/http-message-signatures.php' => config_path('http-message-signatures.php'),
            ], 'http-message-signatures-config');
        }
    }

    private function registerAlgorithm(): void
    {
        $this->app->singleton(AlgorithmInterface::class, function (Application $app) {
            $algorithm = config('http-message-signatures.default_algorithm', 'hmac-sha256');

            return match ($algorithm) {
                'hmac-sha256' => $this->createHmacAlgorithm($app),
                'rsa-sha256' => $this->createRsaAlgorithm($app),
                'ed25519' => $this->createEd25519Algorithm($app),
                default => throw new \InvalidArgumentException("Unsupported algorithm: {$algorithm}"),
            };
        });
    }

    private function createHmacAlgorithm(Application $app): HmacSha256
    {
        $secretKey = config('http-message-signatures.hmac_secret_key');
        if (empty($secretKey)) {
            throw new \RuntimeException('HMAC secret key is not configured. Set HTTP_SIGNATURE_HMAC_SECRET_KEY in your .env file.');
        }

        return new HmacSha256($secretKey);
    }

    private function createRsaAlgorithm(Application $app): RsaSha256
    {
        $privateKeyPath = config('http-message-signatures.rsa_private_key_path');
        if (empty($privateKeyPath) || !file_exists($privateKeyPath)) {
            throw new \RuntimeException('RSA private key path is not configured or file does not exist. Set HTTP_SIGNATURE_RSA_PRIVATE_KEY_PATH in your .env file.');
        }

        $privateKey = file_get_contents($privateKeyPath);
        $publicKey = null;

        $publicKeyPath = config('http-message-signatures.rsa_public_key_path');
        if (!empty($publicKeyPath) && file_exists($publicKeyPath)) {
            $publicKey = file_get_contents($publicKeyPath);
        }

        return new RsaSha256($privateKey, $publicKey);
    }

    private function createEd25519Algorithm(Application $app): Ed25519
    {
        $privateKeyPath = config('http-message-signatures.ed25519_private_key_path');
        if (empty($privateKeyPath) || !file_exists($privateKeyPath)) {
            throw new \RuntimeException('Ed25519 private key path is not configured or file does not exist. Set HTTP_SIGNATURE_ED25519_PRIVATE_KEY_PATH in your .env file.');
        }

        $privateKey = file_get_contents($privateKeyPath);
        $publicKey = null;

        $publicKeyPath = config('http-message-signatures.ed25519_public_key_path');
        if (!empty($publicKeyPath) && file_exists($publicKeyPath)) {
            $publicKey = file_get_contents($publicKeyPath);
        }

        return new Ed25519($privateKey, $publicKey);
    }

    private function registerParser(): void
    {
        $this->app->singleton(StructuredFieldParser::class, fn() => new StructuredFieldParser());
    }

    private function registerComponentDeriver(): void
    {
        $this->app->singleton(ComponentDeriver::class, fn() => new ComponentDeriver());
    }

    private function registerBaseStringBuilder(): void
    {
        $this->app->singleton(SignatureBaseStringBuilder::class, function (Application $app) {
            return new SignatureBaseStringBuilder(
                $app->make(ComponentDeriver::class)
            );
        });
    }

    private function registerSigner(): void
    {
        $this->app->singleton(Signer::class, function (Application $app) {
            return new Signer(
                $app->make(AlgorithmInterface::class),
                $app->make(StructuredFieldParser::class),
                $app->make(SignatureBaseStringBuilder::class)
            );
        });
    }

    private function registerVerifier(): void
    {
        $this->app->singleton(Verifier::class, function (Application $app) {
            return new Verifier(
                $app->make(AlgorithmInterface::class),
                $app->make(StructuredFieldParser::class),
                $app->make(SignatureBaseStringBuilder::class)
            );
        });
    }
}

