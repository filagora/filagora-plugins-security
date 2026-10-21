<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Analysis;

use RuntimeException;

/**
 * The worker was signalled (a deploy, `queue:restart`) and the signal reached an analyzer's
 * process. That is not a failed scan: no scan is recorded and the release stays due for a later one.
 */
class ScanInterrupted extends RuntimeException {}
