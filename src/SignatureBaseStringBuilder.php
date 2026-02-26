<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Builds the signature base string from components.
 */
class SignatureBaseStringBuilder
{
    private ComponentDeriver $componentDeriver;

    public function __construct(?ComponentDeriver $componentDeriver = null)
    {
        $this->componentDeriver = $componentDeriver ?? new ComponentDeriver();
    }

    /**
     * Build the signature base string from components.
     *
     * @param array<string> $components The component identifiers
     * @param MessageInterface $message The HTTP message
     * @param RequestInterface|null $originalRequest The original request (for response signing)
     * @param array<string, mixed> $parameters Additional signature parameters
     * @return string The signature base string
     */
    public function build(
        array $components,
        MessageInterface $message,
        ?RequestInterface $originalRequest = null,
        array $parameters = []
    ): string {
        $componentLines = $this->buildComponentLines($components, $message, $originalRequest);
        $signatureParamsLine = $this->buildSignatureParamsLine($parameters);

        $allLines = array_merge($componentLines, $signatureParamsLine);

        return implode("\n", $allLines);
    }

    /**
     * Build lines for each component.
     *
     * @return array<string>
     */
    private function buildComponentLines(
        array $components,
        MessageInterface $message,
        ?RequestInterface $originalRequest
    ): array {
        $lines = [];

        foreach ($components as $component) {
            $normalizedComponentName = $this->normalizeComponentName($component);
            $componentValue = $this->componentDeriver->deriveComponent($component, $message, $originalRequest);
            $lines[] = $this->formatComponentLine($normalizedComponentName, $componentValue);
        }

        return $lines;
    }

    private function normalizeComponentName(string $component): string
    {
        // Remove parameters like ;name="value" or ;sf
        return preg_replace('/;.*$/', '', $component) ?? $component;
    }

    private function formatComponentLine(string $componentName, string $componentValue): string
    {
        return "\"{$componentName}\": {$componentValue}";
    }

    /**
     * Build the signature-params line if parameters are present.
     *
     * @return array<string>
     */
    private function buildSignatureParamsLine(array $parameters): array
    {
        if (empty($parameters)) {
            return [];
        }

        $parameterString = $this->buildParameterString($parameters);
        if ($parameterString === '') {
            return [];
        }

        return ["\"@signature-params\": {$parameterString}"];
    }

    private function buildParameterString(array $parameters): string
    {
        $parameterParts = $this->buildParameterPartsInCanonicalOrder($parameters);
        $additionalParameterParts = $this->buildAdditionalParameterParts($parameters);

        $allParameterParts = array_merge($parameterParts, $additionalParameterParts);

        if (empty($allParameterParts)) {
            return '';
        }

        return '(' . implode(' ', $allParameterParts) . ')';
    }

    /**
     * Build parameter parts in canonical order.
     *
     * @return array<string>
     */
    private function buildParameterPartsInCanonicalOrder(array $parameters): array
    {
        $parts = [];

        foreach (SignatureParameters::CANONICAL_ORDER as $key) {
            if (isset($parameters[$key])) {
                $value = $parameters[$key];
                $formattedPart = $this->formatParameterPart($key, $value);
                if ($formattedPart !== null) {
                    $parts[] = $formattedPart;
                }
            }
        }

        return $parts;
    }

    /**
     * Build parameter parts for keys not in canonical order.
     * Uses PHP 8.4 array functions for cleaner code.
     *
     * @return array<string>
     */
    private function buildAdditionalParameterParts(array $parameters): array
    {
        $nonCanonicalParameters = array_filter(
            $parameters,
            fn(string $key): bool => !in_array($key, SignatureParameters::CANONICAL_ORDER, true),
            ARRAY_FILTER_USE_KEY
        );

        $parts = [];
        foreach ($nonCanonicalParameters as $key => $value) {
            $formattedPart = $this->formatParameterPart($key, $value);
            if ($formattedPart !== null) {
                $parts[] = $formattedPart;
            }
        }

        return $parts;
    }

    private function formatParameterPart(string $key, mixed $value): ?string
    {
        if (is_string($value)) {
            return "{$key}=\"{$value}\"";
        }

        if (is_int($value)) {
            return "{$key}={$value}";
        }

        return null;
    }
}
