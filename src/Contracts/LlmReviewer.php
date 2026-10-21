<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Contracts;

/**
 * The host's connection to a language model, used by the advisory AI review. The package builds
 * the prompts, batches the source and checks what comes back; it knows no provider. Bind your
 * own implementation (the package binds one that is never configured, so the review is off).
 *
 * `complete()` should throw when the request fails; the review records a failure for that batch.
 * Keep timeouts, retries and usage accounting in the implementation.
 */
interface LlmReviewer
{
    /**
     * Whether a model can be called: credentials and a model name are set.
     */
    public function isConfigured(): bool;

    /**
     * The model's name, recorded with each review so a change of model shows in the history.
     */
    public function model(): string;

    /**
     * Send the messages and answer the text of the model's reply.
     *
     * @param  list<array{role: string, content: string}>  $messages
     */
    public function complete(array $messages): string;
}
