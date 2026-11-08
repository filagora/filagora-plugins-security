<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Notifications;

use Filagora\Plugins\Filament\Resources\PluginReleases\PluginReleaseResource;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Models\SecurityScan;
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
 *
 * A host that wants other words or another layout extends this class, overrides `toMail()` and names
 * the class in `filagora-plugins-security.mail.notification`; the scan the mail is about is `$scan`
 * (none for a lifted hold).
 */
class SecurityNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * @param  array<string, scalar|null>  $replace  Values for the placeholders in the words.
     * @param  list<string>  $details  Extra lines under the intro.
     * @param  SecurityScan|null  $scan  The scan the mail is about, when there is one.
     */
    public function __construct(
        public readonly string $kind,
        public readonly PluginRelease $release,
        public readonly array $replace = [],
        public readonly array $details = [],
        public readonly bool $forStaff = false,
        public readonly ?SecurityScan $scan = null,
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
        $mail = $this->fromSupportAddress(new MailMessage)
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

    /**
     * Like the plugin mail, security mail comes from the plugin support address
     * (`filagora-plugins.mail.support_email`) when it is a valid address, else from the application's own.
     */
    private function fromSupportAddress(MailMessage $message): MailMessage
    {
        $configured = trim((string) config('filagora-plugins.mail.support_email'));
        $address = filter_var($configured, FILTER_VALIDATE_EMAIL) !== false ? $configured : trim((string) config('mail.from.address', ''));

        if (filter_var($address, FILTER_VALIDATE_EMAIL) === false) {
            return $message;
        }

        $name = config('mail.from.name');

        return $message->from($address, is_string($name) && $name !== '' ? $name : null);
    }
}
