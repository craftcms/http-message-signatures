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
        $params = [];

        if ($config->created !== null) {
            $params['created'] = $config->created;
        }

        if ($config->expiresAfter !== null && $config->created !== null) {
            $params['expires'] = $config->created + $config->expiresAfter;
        }

        if ($config->nonce !== null) {
            $params['nonce'] = $config->nonce;
        }

        $algId = $algorithm->getAlgorithmId();

        if ($algId !== '') {
            $params['alg'] = $algId;
        }

        if ($config->keyid !== null) {
            $params['keyid'] = $config->keyid;
        }

        if ($config->tag !== null) {
            $params['tag'] = $config->tag;
        }

        return Parameters::fromAssociative($params);
    }
}
