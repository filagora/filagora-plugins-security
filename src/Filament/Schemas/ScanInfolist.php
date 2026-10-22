<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Filament\Schemas;

use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filament\Infolists\Components\TextEntry;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

/**
 * One scan, laid out for a modal or a view page: when, by whom and how it went, which analyzers ran
 * and what they found. An AI review also shows its explanations, the code quoted and the suggested fix.
 */
final class ScanInfolist
{
    public static function configure(Schema $schema): Schema
    {
        return $schema->components([
            Section::make(__('filagora-plugins-security::screens.scan.section'))
                ->columns(2)
                ->schema([
                    TextEntry::make('release.plugin.name')->label(__('filagora-plugins-security::screens.scan.plugin')),
                    TextEntry::make('release.version')->label(__('filagora-plugins-security::screens.scan.release')),
                    TextEntry::make('scanner_version')->label(__('filagora-plugins-security::screens.scan.scanner_version')),
                    TextEntry::make('triggered_by')
                        ->label(__('filagora-plugins-security::screens.scan.trigger'))
                        ->badge()
                        ->formatStateUsing(fn (ScanTrigger $state): string => $state->label()),
                    TextEntry::make('status')
                        ->badge()
                        ->formatStateUsing(fn (ScanStatus $state): string => $state->label())
                        ->color(fn (ScanStatus $state): string => $state->color()),
                    TextEntry::make('highest_severity')
                        ->label(__('filagora-plugins-security::screens.scan.severity'))
                        ->badge()
                        ->placeholder('-')
                        ->formatStateUsing(fn (?ScanSeverity $state): string => $state?->label() ?? '-')
                        ->color(fn (?ScanSeverity $state): string => $state?->color() ?? 'gray'),
                    TextEntry::make('triggeredByUser.email')->label(__('filagora-plugins-security::screens.scan.triggered_by'))->placeholder(__('filagora-plugins-security::screens.scan.system')),
                    TextEntry::make('queued_at')->dateTime()->placeholder('-'),
                    TextEntry::make('started_at')->dateTime()->placeholder('-'),
                    TextEntry::make('finished_at')->dateTime()->placeholder('-'),
                    TextEntry::make('error')
                        ->columnSpanFull()
                        ->color('danger')
                        ->visible(fn (SecurityScan $record): bool => filled($record->error)),
                ]),
            Section::make(__('filagora-plugins-security::screens.scan.analyzers'))
                ->schema([
                    TextEntry::make('analyzer_versions')
                        ->hiddenLabel()
                        ->state(fn (SecurityScan $record): string => self::analyzers($record))
                        ->extraAttributes(['class' => 'whitespace-pre-wrap'])
                        ->placeholder(__('filagora-plugins-security::screens.scan.none_recorded')),
                ]),
            Section::make(__('filagora-plugins-security::screens.scan.findings'))
                ->schema([
                    TextEntry::make('findings')
                        ->hiddenLabel()
                        ->state(fn (SecurityScan $record): string => self::findings($record))
                        ->extraAttributes(['class' => 'whitespace-pre-wrap'])
                        ->placeholder(__('filagora-plugins-security::screens.scan.no_findings')),
                ]),
        ]);
    }

    public static function analyzers(SecurityScan $scan): string
    {
        return collect($scan->analyzer_versions ?? [])
            ->map(fn (array $meta, string $name): string => sprintf(
                '%s: v%s (%s)%s',
                $name,
                $meta['version'] ?? '?',
                $meta['status'] ?? 'completed',
                isset($meta['note']) ? ' - '.$meta['note'] : '',
            ))
            ->implode("\n");
    }

    public static function findings(SecurityScan $scan): string
    {
        return collect($scan->findings ?? [])
            ->map(fn (array $finding): string => self::finding($finding))
            ->implode("\n");
    }

    /**
     * A finding in one line: severity, analyzer, title and where it is.
     *
     * @param  array<string, mixed>  $finding
     */
    public static function summary(array $finding): string
    {
        return sprintf(
            '[%s] %s - %s%s',
            strtoupper((string) ($finding['severity'] ?? '?')),
            $finding['analyzer'] ?? '?',
            $finding['title'] ?? $finding['rule_id'] ?? 'finding',
            isset($finding['file']) ? ' ('.$finding['file'].(isset($finding['line']) ? ':'.$finding['line'] : '').')' : '',
        );
    }

    /**
     * One finding as text: severity, analyzer, title, where it is and which rule raised it, then any
     * explanation, quoted code and suggested fix the analyzer gave.
     *
     * @param  array<string, mixed>  $finding
     */
    public static function finding(array $finding): string
    {
        $where = isset($finding['file']) ? ' '.__('filagora-plugins-security::screens.scan.in').' '.$finding['file'].(isset($finding['line']) ? ':'.$finding['line'] : '') : '';
        $text = sprintf(
            '[%s] %s - %s%s (%s)%s',
            strtoupper((string) ($finding['severity'] ?? '?')),
            $finding['analyzer'] ?? '?',
            $finding['title'] ?? $finding['rule_id'] ?? 'finding',
            $where,
            $finding['rule_id'] ?? '?',
            filled($finding['confidence'] ?? null) ? ', '.__('filagora-plugins-security::screens.scan.confidence').': '.$finding['confidence'] : '',
        );

        foreach (['explanation' => 'why', 'snippet' => 'code', 'suggestion' => 'fix'] as $key => $label) {
            if (filled($finding[$key] ?? null)) {
                $text .= "\n    ".__("filagora-plugins-security::screens.scan.{$label}").': '.str_replace("\n", "\n    ", (string) $finding[$key]);
            }
        }

        return $text;
    }
}
