<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Exception;

/**
 * Exception thrown when a key is invalid.
 */
class InvalidKeyException extends \RuntimeException implements ExceptionInterface {}
