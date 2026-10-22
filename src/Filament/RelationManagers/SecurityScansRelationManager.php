<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Filament\RelationManagers;

use BackedEnum;
use Filagora\PluginsSecurity\Enums\ScanKind;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Exceptions\SecurityRefused;
use Filagora\PluginsSecurity\Filament\Schemas\ScanInfolist;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Services\AcceptedFindings;
use Filagora\PluginsSecurity\Services\FindingReviews;
use Filagora\PluginsSecurity\Support\StaffAccess;
use Filament\Actions\Action;
use Filament\Actions\ViewAction;
use Filament\Forms\Components\CheckboxList;
use Filament\Forms\Components\Textarea;
use Filament\Notifications\Notification;
use Filament\Resources\RelationManagers\RelationManager;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Every scan of a release, newest first: the standard scans and the AI reviews. A moderator opens
 * one to read it and can mark its findings reviewed and acceptable for the plugin.
 */
class SecurityScansRelationManager extends RelationManager
{
    protected static string $relationship = 'securityScans';

    public static function getTitle(Model $ownerRecord, string $pageClass): string
    {
        return __('filagora-plugins-security::screens.history.title');
    }

    public static function canViewForRecord(Model $ownerRecord, string $pageClass): bool
    {
        return StaffAccess::allowed();
    }

    public function infolist(Schema $schema): Schema
    {
        return ScanInfolist::configure($schema);
    }

    public function table(Table $table): Table
    {
        return $table
            ->recordTitleAttribute('scanner_version')
            ->defaultSort('id', 'desc')
            ->description(__('filagora-plugins-security::screens.history.description'))
            ->columns([
                TextColumn::make('kind')
                    ->label(__('filagora-plugins-security::screens.history.kind'))
                    ->badge()
                    ->formatStateUsing(fn (ScanKind $state): string => $state->label())
                    ->color(fn (ScanKind $state): string => $state === ScanKind::LLM ? 'info' : 'gray'),
                TextColumn::make('scanner_version')->label(__('filagora-plugins-security::screens.history.scanner'))->sortable(),
                TextColumn::make('status')
                    ->badge()
                    ->formatStateUsing(fn (ScanStatus $state): string => $state->label())
                    ->color(fn (ScanStatus $state): string => $state->color())
                    ->sortable(),
                TextColumn::make('highest_severity')
                    ->label(__('filagora-plugins-security::screens.history.severity'))
                    ->badge()
                    ->placeholder('-')
                    ->formatStateUsing(fn (?ScanSeverity $state): string => $state?->label() ?? '-')
                    ->color(fn (?ScanSeverity $state): string => $state?->color() ?? 'gray')
                    ->sortable(),
                TextColumn::make('findings_count')
                    ->label(__('filagora-plugins-security::screens.history.findings'))
                    ->state(fn (SecurityScan $record): int => count($record->findings ?? [])),
                TextColumn::make('triggered_by')
                    ->label(__('filagora-plugins-security::screens.history.trigger'))
                    ->badge()
                    ->formatStateUsing(fn (ScanTrigger $state): string => $state->label()),
                TextColumn::make('finished_at')->dateTime()->placeholder('-')->sortable(),
            ])
            ->filters([
                SelectFilter::make('kind')->options(self::options(ScanKind::cases())),
                SelectFilter::make('status')->options(self::options(ScanStatus::cases())),
                SelectFilter::make('highest_severity')->label(__('filagora-plugins-security::screens.history.severity'))->options(self::options(ScanSeverity::cases())),
                SelectFilter::make('triggered_by')->label(__('filagora-plugins-security::screens.history.trigger'))->options(self::options(ScanTrigger::cases())),
            ])
            ->recordActions([
                ViewAction::make(),
                $this->markReviewed(),
            ]);
    }

    private function markReviewed(): Action
    {
        return Action::make('markFindingsReviewed')
            ->label(__('filagora-plugins-security::screens.history.accept'))
            ->icon('heroicon-o-hand-thumb-up')
            ->visible(fn (SecurityScan $record): bool => $record->kind === ScanKind::STANDARD && $this->findingOptions($record) !== [])
            ->schema([
                CheckboxList::make('fingerprints')
                    ->label(__('filagora-plugins-security::screens.history.accept_findings'))
                    ->options(fn (SecurityScan $record): array => $this->findingOptions($record))
                    ->required(),
                Textarea::make('note')->label(__('filagora-plugins-security::screens.history.accept_note'))->rows(3)->maxLength(4000),
            ])
            ->action(function (SecurityScan $record, array $data): void {
                $moderator = auth()->user();

                if (! $moderator instanceof Authenticatable || $record->release === null) {
                    return;
                }

                try {
                    foreach ((array) $data['fingerprints'] as $fingerprint) {
                        app(FindingReviews::class)->accept($record->release, $record, (string) $fingerprint, $moderator, $data['note'] ?? null);
                    }
                } catch (SecurityRefused $refused) {
                    Notification::make()->title($refused->getMessage())->danger()->send();

                    return;
                }

                Notification::make()->title(__('filagora-plugins-security::screens.history.accepted'))->success()->send();
            });
    }

    /**
     * The scan's findings that have a fingerprint, as checkbox options; one already accepted is marked.
     *
     * @return array<string, string>
     */
    private function findingOptions(SecurityScan $scan): array
    {
        $accepted = $scan->release === null ? [] : array_flip(app(AcceptedFindings::class)->for($scan->release));
        $options = [];

        foreach ($scan->findings ?? [] as $finding) {
            $fingerprint = (string) ($finding['fingerprint'] ?? '');

            if ($fingerprint === '') {
                continue;
            }

            $options[$fingerprint] = ScanInfolist::summary($finding).(isset($accepted[$fingerprint]) ? ' ('.__('filagora-plugins-security::screens.history.already_accepted').')' : '');
        }

        return $options;
    }

    /**
     * @param  list<BackedEnum>  $cases
     * @return array<string, string>
     */
    private static function options(array $cases): array
    {
        return collect($cases)
            ->mapWithKeys(fn (BackedEnum $case): array => [(string) $case->value => method_exists($case, 'label') ? $case->label() : (string) $case->value])
            ->all();
    }
}
