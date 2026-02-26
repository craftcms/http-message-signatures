<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Bakame\Http\StructuredFields\ByteSequence;
use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\Token;

/**
 * Parser for HTTP Structured Fields (RFC 8941) used in signature-input and signature headers.
 * Uses bakame/http-structured-fields for parsing and formatting.
 */
class StructuredFieldParser
{
    /**
     * Parse a signature-input header value.
     *
     * @param string $value The signature-input header value
     * @return array<string, array{components: array<string>, params: array<string, mixed>}>
     */
    public function parseSignatureInput(string $value): array
    {
        // signature-input is a Dictionary where each value is an InnerList with parameters
        $dictionary = Dictionary::fromHttpValue($value);
        $signatures = [];

        foreach ($dictionary as $key => $innerList) {
            if (!$innerList instanceof InnerList) {
                continue;
            }

            $components = $this->extractComponentsFromInnerList($innerList);
            $parameters = $this->extractParametersFromInnerList($innerList);

            $signatures[(string) $key] = [
                'components' => $components,
                'params' => $parameters,
            ];
        }

        return $signatures;
    }

    /**
     * Parse a signature header value.
     *
     * @param string $value The signature header value
     * @return array<string, string> Map of signature ID to signature value
     */
    public function parseSignature(string $value): array
    {
        // signature is a Dictionary where each value is a ByteSequence
        $dictionary = Dictionary::fromHttpValue($value);
        $signatures = [];

        foreach ($dictionary as $key => $item) {
            if ($item instanceof Item) {
                $byteSeq = $item->value();
                if ($byteSeq instanceof ByteSequence) {
                    $signatures[(string) $key] = $byteSeq->toBase64();
                }
            }
        }

        return $signatures;
    }

    /**
     * Format a signature-input value.
     *
     * @param string $signatureId The signature identifier
     * @param array<string> $components The component identifiers
     * @param array<string, mixed> $parameters The signature parameters
     * @return string The formatted signature-input value
     */
    public function formatSignatureInput(
        string $signatureId,
        array $components,
        array $parameters = []
    ): string {
        $innerListItems = $this->buildInnerListItemsFromComponents($components);
        $innerList = InnerList::from(...$innerListItems);
        $innerListWithParameters = $this->attachParametersToInnerList($innerList, $parameters);

        $dictionary = Dictionary::fromAssociative([$signatureId => $innerListWithParameters]);

        return $dictionary->toHttpValue();
    }

    /**
     * Format a signature value.
     *
     * @param string $signatureId The signature identifier
     * @param string $signature The base64-encoded signature
     * @return string The formatted signature value
     */
    public function formatSignature(string $signatureId, string $signature): string
    {
        $byteSequence = ByteSequence::fromBase64($signature);
        $item = Item::from($byteSequence);
        $dictionary = Dictionary::fromAssociative([$signatureId => $item]);

        return $dictionary->toHttpValue();
    }

    /**
     * Extract component identifiers from an inner list.
     *
     * @return array<string>
     */
    private function extractComponentsFromInnerList(InnerList $innerList): array
    {
        $components = [];

        foreach ($innerList->value() as $item) {
            if ($item instanceof Item) {
                $value = $item->value();
                if ($value instanceof Token || is_string($value)) {
                    $components[] = (string) $value;
                }
            }
        }

        return $components;
    }

    /**
     * Extract parameters from an inner list.
     *
     * @return array<string, mixed>
     */
    private function extractParametersFromInnerList(InnerList $innerList): array
    {
        $parameters = [];

        foreach ($innerList->parameters() as $paramKey => $paramValue) {
            $paramValueObj = $paramValue->value();
            if (is_int($paramValueObj)) {
                $parameters[(string) $paramKey] = $paramValueObj;
            } elseif (is_string($paramValueObj) || $paramValueObj instanceof Token) {
                $parameters[(string) $paramKey] = (string) $paramValueObj;
            }
        }

        return $parameters;
    }

    /**
     * Build inner list items from component identifiers.
     *
     * @return array<Item>
     */
    private function buildInnerListItemsFromComponents(array $components): array
    {
        $items = [];

        foreach ($components as $component) {
            $items[] = Item::from($component);
        }

        return $items;
    }

    /**
     * Attach parameters to an inner list in canonical order.
     *
     * @param array<string, mixed> $parameters
     */
    private function attachParametersToInnerList(InnerList $innerList, array $parameters): InnerList
    {
        $innerListWithCanonicalParameters = $this->attachCanonicalParameters($innerList, $parameters);
        $innerListWithAllParameters = $this->attachRemainingParameters($innerListWithCanonicalParameters, $parameters);

        return $innerListWithAllParameters;
    }

    /**
     * Attach parameters in canonical order.
     *
     * @param array<string, mixed> $parameters
     */
    private function attachCanonicalParameters(InnerList $innerList, array $parameters): InnerList
    {
        $result = $innerList;

        foreach (SignatureParameters::CANONICAL_ORDER as $key) {
            if (isset($parameters[$key])) {
                $value = $parameters[$key];
                $result = $this->attachParameterIfValid($result, $key, $value);
            }
        }

        return $result;
    }

    /**
     * Attach remaining parameters not in canonical order.
     * Uses PHP 8.4 array_filter with ARRAY_FILTER_USE_KEY for cleaner code.
     *
     * @param array<string, mixed> $parameters
     */
    private function attachRemainingParameters(InnerList $innerList, array $parameters): InnerList
    {
        $result = $innerList;

        $nonCanonicalParameters = array_filter(
            $parameters,
            fn(string $key): bool => !in_array($key, SignatureParameters::CANONICAL_ORDER, true),
            ARRAY_FILTER_USE_KEY
        );

        foreach ($nonCanonicalParameters as $key => $value) {
            $result = $this->attachParameterIfValid($result, $key, $value);
        }

        return $result;
    }

    /**
     * Attach a parameter to an inner list if the value is valid.
     */
    private function attachParameterIfValid(InnerList $innerList, string $key, mixed $value): InnerList
    {
        if (is_int($value) || is_string($value)) {
            return $innerList->withParameter(Token::from($key), Item::from($value));
        }

        return $innerList;
    }
}
