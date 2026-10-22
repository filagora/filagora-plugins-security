<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Filament\Schemas;

use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filament\Infolists\Components\TextEntry;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

/**
 * An AI review: advisory output, with the model that gave it, so a moderator can weigh it.
 */
final class LlmReviewInfolist
{
    public static function configure(Schema $schema): Schema
    {
        return $schema->components([
            Section::make(__('filagora-plugins-security::screens.ai.section'))
                ->description(__('filagora-plugins-security::screens.ai.description'))
                ->columns(2)
                ->schema([
                    TextEntry::make('status')
                        ->label(__('filagora-plugins-security::screens.ai.status'))
                        ->badge()
                        ->formatStateUsing(fn (ScanStatus $state): string => $state->label())
                        ->color(fn (ScanStatus $state): string => $state->color()),
                    TextEntry::make('highest_severity')
                        ->label(__('filagora-plugins-security::screens.ai.severity'))
                        ->badge()
                        ->placeholder('-')
                        ->formatStateUsing(fn (?ScanSeverity $state): string => $state?->label() ?? '-')
                        ->color(fn (?ScanSeverity $state): string => $state?->color() ?? 'gray'),
                    TextEntry::make('model')
                        ->label(__('filagora-plugins-security::screens.ai.model'))
                        ->state(fn (SecurityScan $record): string => (string) ($record->analyzer_versions['llm']['version'] ?? '-')),
                    TextEntry::make('triggeredByUser.email')->label(__('filagora-plugins-security::screens.ai.requested_by'))->placeholder(__('filagora-plugins-security::screens.scan.system')),
                    TextEntry::make('queued_at')->dateTime()->placeholder('-'),
                    TextEntry::make('finished_at')->dateTime()->placeholder('-'),
                    TextEntry::make('error')
                        ->label(__('filagora-plugins-security::screens.ai.error'))
                        ->columnSpanFull()
                        ->color('danger')
                        ->visible(fn (SecurityScan $record): bool => filled($record->error)),
                ]),
            Section::make(__('filagora-plugins-security::screens.scan.findings'))
                ->schema([
                    TextEntry::make('findings')
                        ->hiddenLabel()
                        ->state(fn (SecurityScan $record): string => ScanInfolist::findings($record))
                        ->extraAttributes(['class' => 'whitespace-pre-wrap'])
                        ->placeholder(__('filagora-plugins-security::screens.scan.no_findings')),
                ]),
        ]);
    }
}
