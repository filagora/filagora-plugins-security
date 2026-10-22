<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Filament;

use Filagora\Plugins\Models\PluginRelease;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanStatus;
use Filagora\PluginsSecurity\Models\SecurityScan;
use Filagora\PluginsSecurity\Support\Config;
use Filagora\PluginsSecurity\Support\StaffAccess;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Illuminate\Database\Eloquent\Builder;

/**
 * The columns and filters the package adds to the release list.
 */
final class ReleaseScreenParts
{
    public static function severityColumn(): TextColumn
    {
        return TextColumn::make('latestSecurityScan.highest_severity')
            ->label(__('filagora-plugins-security::screens.column.scan'))
            ->badge()
            ->visible(fn (): bool => StaffAccess::allowed())
            ->placeholder(__('filagora-plugins-security::screens.column.not_scanned'))
            ->formatStateUsing(function ($state, PluginRelease $record): string {
                $scan = $record->latestSecurityScan;

                return match (true) {
                    $scan === null => __('filagora-plugins-security::screens.column.not_scanned'),
                    $scan->status !== ScanStatus::COMPLETED => $scan->status->label(),
                    default => $scan->severity()->label(),
                };
            })
            ->color(function ($state, PluginRelease $record): string {
                $scan = $record->latestSecurityScan;

                return match (true) {
                    $scan === null => 'gray',
                    $scan->status === ScanStatus::COMPLETED => $scan->severity()->color(),
                    default => $scan->status->color(),
                };
            });
    }

    public static function versionColumn(): TextColumn
    {
        $current = Config::scannerVersion();

        return TextColumn::make('latestSecurityScan.scanner_version')
            ->label(__('filagora-plugins-security::screens.column.scan_version'))
            ->badge()
            ->visible(fn (): bool => StaffAccess::allowed())
            ->placeholder(__('filagora-plugins-security::screens.column.not_scanned'))
            ->formatStateUsing(fn ($state): string => 'v'.$state)
            ->color(fn ($state): string => (int) $state >= $current ? 'success' : 'warning')
            ->tooltip(fn (PluginRelease $record): ?string => $record->latestSecurityScan === null
                ? null
                : ($record->latestSecurityScan->scanner_version >= $current
                    ? __('filagora-plugins-security::screens.column.current', ['version' => $current])
                    : __('filagora-plugins-security::screens.column.stale', ['version' => $current])));
    }

    public static function severityFilter(): SelectFilter
    {
        return SelectFilter::make('security_severity')
            ->label(__('filagora-plugins-security::screens.filter.scan'))
            ->options(collect(ScanSeverity::cases())->mapWithKeys(fn (ScanSeverity $severity): array => [$severity->value => $severity->label()])->all()
                + ['unscanned' => __('filagora-plugins-security::screens.filter.unscanned')])
            ->visible(fn (): bool => StaffAccess::allowed())
            ->query(function (Builder $query, array $data): Builder {
                $value = $data['value'] ?? null;

                return match (true) {
                    blank($value) => $query,
                    $value === 'unscanned' => $query->whereNull('latest_security_scan_id'),
                    default => $query->whereHas('latestSecurityScan', fn (Builder $scan) => $scan->where('highest_severity', $value)),
                };
            });
    }

    public static function versionFilter(): SelectFilter
    {
        $current = Config::scannerVersion();

        return SelectFilter::make('security_version')
            ->label(__('filagora-plugins-security::screens.filter.scan_version'))
            ->visible(fn (): bool => StaffAccess::allowed())
            ->options(fn (): array => SecurityScan::query()
                ->where('kind', 'standard')
                ->distinct()
                ->orderByDesc('scanner_version')
                ->pluck('scanner_version')
                ->mapWithKeys(fn ($version): array => [(string) $version => 'v'.$version])
                ->all() + [
                    'stale' => __('filagora-plugins-security::screens.filter.stale', ['version' => $current]),
                    'unscanned' => __('filagora-plugins-security::screens.filter.unscanned'),
                ])
            ->query(function (Builder $query, array $data) use ($current): Builder {
                $value = $data['value'] ?? null;

                return match (true) {
                    blank($value) => $query,
                    $value === 'unscanned' => $query->whereNull('latest_security_scan_id'),
                    $value === 'stale' => $query->whereHas('latestSecurityScan', fn (Builder $scan) => $scan->where('scanner_version', '<', $current)),
                    default => $query->whereHas('latestSecurityScan', fn (Builder $scan) => $scan->where('scanner_version', (int) $value)),
                };
            });
    }
}
