<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Filament;

use Closure;
use Filagora\Plugins\Enums\PluginStatus;
use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Exceptions\SecurityRefused;
use Filagora\PluginsSecurity\Filament\Schemas\LlmReviewInfolist;
use Filagora\PluginsSecurity\Filament\Schemas\ScanInfolist;
use Filagora\PluginsSecurity\Jobs\LlmReviewJob;
use Filagora\PluginsSecurity\Jobs\ScanReleaseJob;
use Filagora\PluginsSecurity\Listeners\SendSecurityMail;
use Filagora\PluginsSecurity\Services\LlmReviews;
use Filagora\PluginsSecurity\Services\Quarantine;
use Filagora\PluginsSecurity\Support\StaffAccess;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Forms\Components\Textarea;
use Filament\Notifications\Notification;
use Filament\Schemas\Schema;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Collection;

/**
 * The security actions on the release list. They show only to someone who may act on scans; each
 * hands the work to a service or a job, which checks the same thing again.
 */
final class SecurityActions
{
    public static function latestScan(): Action
    {
        return Action::make('securityScan')
            ->label(__('filagora-plugins-security::screens.action.latest_scan'))
            ->icon('heroicon-o-shield-check')
            ->modalHeading(__('filagora-plugins-security::screens.action.latest_scan_heading'))
            ->modalSubmitAction(false)
            ->modalCancelActionLabel(__('filagora-plugins-security::screens.action.close'))
            ->visible(fn (PluginRelease $record): bool => $record->latest_security_scan_id !== null && StaffAccess::allowed())
            ->schema(fn (Schema $schema, PluginRelease $record): Schema => ScanInfolist::configure($schema)->record($record->latestSecurityScan));
    }

    public static function latestReview(): Action
    {
        return Action::make('aiReviewResult')
            ->label(__('filagora-plugins-security::screens.action.ai_result'))
            ->icon('heroicon-o-sparkles')
            ->modalHeading(__('filagora-plugins-security::screens.action.ai_result_heading'))
            ->modalSubmitAction(false)
            ->modalCancelActionLabel(__('filagora-plugins-security::screens.action.close'))
            ->visible(fn (PluginRelease $record): bool => $record->latestLlmReview !== null && StaffAccess::allowed())
            ->schema(fn (Schema $schema, PluginRelease $record): Schema => LlmReviewInfolist::configure($schema)->record($record->latestLlmReview));
    }

    public static function more(): ActionGroup
    {
        return ActionGroup::make([
            self::aiReview(),
            self::rescan(),
            self::quarantine(),
            self::clearQuarantine(),
            self::emailAuthor(),
        ])->visible(fn (): bool => StaffAccess::allowed());
    }

    public static function rescanSeveral(): BulkAction
    {
        return BulkAction::make('rescanSecurity')
            ->label(__('filagora-plugins-security::screens.action.rescan_bulk'))
            ->icon('heroicon-o-shield-check')
            ->requiresConfirmation()
            ->visible(fn (): bool => StaffAccess::allowed())
            ->action(function (Collection $records): void {
                if (! StaffAccess::allowed()) {
                    return;
                }

                foreach ($records as $record) {
                    ScanReleaseJob::dispatch((int) $record->getKey(), ScanTrigger::MANUAL, auth()->id());
                }

                Notification::make()->success()->title(__('filagora-plugins-security::screens.action.rescans_queued'))->send();
            })
            ->deselectRecordsAfterCompletion();
    }

    private static function aiReview(): Action
    {
        return Action::make('aiReview')
            ->label(__('filagora-plugins-security::screens.action.ai_review'))
            ->icon('heroicon-o-sparkles')
            ->visible(fn (): bool => app(LlmReviews::class)->isAvailable() && StaffAccess::allowed())
            ->requiresConfirmation()
            ->modalHeading(__('filagora-plugins-security::screens.action.ai_review_heading'))
            ->modalDescription(__('filagora-plugins-security::screens.action.ai_review_help'))
            ->action(function (PluginRelease $record): void {
                if (! StaffAccess::allowed()) {
                    return;
                }

                LlmReviewJob::dispatch((int) $record->getKey(), auth()->id());

                Notification::make()->success()->title(__('filagora-plugins-security::screens.action.ai_review_queued'))->send();
            });
    }

    private static function rescan(): Action
    {
        return Action::make('rescan')
            ->label(__('filagora-plugins-security::screens.action.rescan'))
            ->icon('heroicon-o-shield-check')
            ->requiresConfirmation()
            ->action(function (PluginRelease $record): void {
                if (! StaffAccess::allowed()) {
                    return;
                }

                ScanReleaseJob::dispatch((int) $record->getKey(), ScanTrigger::MANUAL, auth()->id());

                Notification::make()->success()->title(__('filagora-plugins-security::screens.action.rescan_queued'))->send();
            });
    }

    private static function quarantine(): Action
    {
        return Action::make('quarantine')
            ->label(__('filagora-plugins-security::screens.action.quarantine'))
            ->icon('heroicon-o-shield-exclamation')
            ->color('danger')
            ->visible(fn (PluginRelease $record): bool => ! $record->isQuarantined() && in_array($record->status, [PluginStatus::ACTIVE, PluginStatus::MODERATED], true))
            ->schema([Textarea::make('note')->label(__('filagora-plugins-security::screens.action.quarantine_reason'))->required()->rows(3)->maxLength(4000)])
            ->action(fn (PluginRelease $record, array $data) => self::run(
                fn (Authenticatable $moderator) => app(Quarantine::class)->quarantine($record, $moderator, (string) $data['note']),
                __('filagora-plugins-security::screens.action.quarantined'),
            ));
    }

    private static function clearQuarantine(): Action
    {
        return Action::make('clearQuarantine')
            ->label(__('filagora-plugins-security::screens.action.clear'))
            ->icon('heroicon-o-check-circle')
            ->color('success')
            ->visible(fn (PluginRelease $record): bool => $record->isQuarantined())
            ->schema([Textarea::make('note')->label(__('filagora-plugins-security::screens.action.clear_reason'))->required()->rows(3)->maxLength(4000)])
            ->action(fn (PluginRelease $record, array $data) => self::run(
                fn (Authenticatable $moderator) => app(Quarantine::class)->clear($record, $moderator, (string) $data['note']),
                __('filagora-plugins-security::screens.action.cleared'),
            ));
    }

    private static function emailAuthor(): Action
    {
        return Action::make('emailScanResultToAuthor')
            ->label(__('filagora-plugins-security::screens.action.email_author'))
            ->icon('heroicon-o-envelope')
            ->requiresConfirmation()
            ->visible(fn (PluginRelease $record): bool => $record->latestSecurityScan?->isFinished() ?? false)
            ->action(function (PluginRelease $record): void {
                $scan = $record->latestSecurityScan;

                if ($scan === null || ! StaffAccess::allowed()) {
                    return;
                }

                app(SendSecurityMail::class)->tellAuthorsTheResult($record, $scan);

                Notification::make()->success()->title(__('filagora-plugins-security::screens.action.email_author_sent'))->send();
            });
    }

    /**
     * @param  Closure(Authenticatable): mixed  $work
     */
    private static function run(Closure $work, string $done): void
    {
        $user = auth()->user();

        if (! $user instanceof Authenticatable) {
            return;
        }

        try {
            $work($user);
        } catch (SecurityRefused $refused) {
            Notification::make()->title($refused->getMessage())->danger()->send();

            return;
        }

        Notification::make()->title($done)->success()->send();
    }
}
