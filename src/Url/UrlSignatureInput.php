<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Parameters;
use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Signer;

final class UrlSignatureInput
{
    public static function fromConfig(UrlSigningConfig $config, AlgorithmInterface $algorithm): InnerList
    {
        $componentItems = array_map(Signer::parseComponentIdentifier(...), $config->components);

        return InnerList::fromAssociative($componentItems, self::parameters($config, $algorithm));
    }

    private static function parameters(UrlSigningConfig $config, AlgorithmInterface $algorithm): Parameters
    {
        $algId = $algorithm->getAlgorithmId();

        $params = array_filter([
            'created' => $config->created,
            'expires' => $config->created !== null && $config->expiresAfter !== null
                ? $config->created + $config->expiresAfter
                : null,
            'nonce' => $config->nonce,
            'alg' => $algId !== '' ? $algId : null,
            'keyid' => $config->keyid,
            'tag' => $config->tag,
        ], static fn (mixed $value): bool => $value !== null);

        return Parameters::fromAssociative($params);
    }
}
