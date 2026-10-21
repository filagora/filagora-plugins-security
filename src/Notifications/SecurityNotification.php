<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Notifications;

use Filagora\Plugins\Filament\Resources\PluginReleases\PluginReleaseResource;
use Filagora\Plugins\Models\PluginRelease;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Route;
use Throwable;

/**
 * One email for every security event the package sends. The words come from
 * `filagora-plugins-security::notifications.{kind}` (a `subject`, an `intro` and an `action`);
 * override the language file to reword them. Authors are linked to the route named in
 * `filagora-plugins.routes.plugin`, staff to the release's page in the dashboard, when there is one.
 */
final class SecurityNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * @param  array<string, scalar|null>  $replace  Values for the placeholders in the words.
     * @param  list<string>  $details  Extra lines under the intro.
     */
    public function __construct(
        public readonly string $kind,
        public readonly PluginRelease $release,
        public readonly array $replace = [],
        public readonly array $details = [],
        public readonly bool $forStaff = false,
    ) {}

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $mail = (new MailMessage)
            ->subject(__("filagora-plugins-security::notifications.{$this->kind}.subject", $this->replace))
            ->line(__("filagora-plugins-security::notifications.{$this->kind}.intro", $this->replace));

        foreach ($this->details as $detail) {
            if (trim($detail) !== '') {
                $mail->line($detail);
            }
        }

        $url = $this->forStaff ? $this->staffUrl() : $this->publicUrl();

        return $url === null ? $mail : $mail->action(__("filagora-plugins-security::notifications.{$this->kind}.action"), $url);
    }

    private function publicUrl(): ?string
    {
        $name = config('filagora-plugins.routes.plugin');

        return is_string($name) && $name !== '' && Route::has($name) ? route($name, ['plugin' => $this->release->plugin]) : null;
    }

    private function staffUrl(): ?string
    {
        try {
            return PluginReleaseResource::getUrl('edit', ['record' => $this->release]);
        } catch (Throwable) {
            return null;
        }
    }
}
