<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Bakame\Http\StructuredFields\Item;
use InvalidArgumentException;
use League\Uri\Components\URLSearchParams;
use Psr\Http\Message\RequestInterface;

final class QueryParamComponent
{
    /**
     * RFC 9421 Section 2.2.8: Derive a specific query parameter value.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.8
     */
    public static function derive(Item $componentId, RequestInterface $request): string
    {
        $paramName = $componentId->parameterByKey('name');

        if ($paramName === null || !is_string($paramName)) {
            throw new InvalidArgumentException('@query-param requires a "name" parameter');
        }

        $matchedValues = URLSearchParams::fromUri($request->getUri())->getAll(rawurldecode($paramName));

        if (count($matchedValues) > 1) {
            throw new InvalidArgumentException("Query parameter \"{$paramName}\" occurs more than once in request");
        }

        if (count($matchedValues) === 1) {
            return rawurlencode($matchedValues[0]);
        }

        throw new InvalidArgumentException("Query parameter \"{$paramName}\" not found in request");
    }
}
