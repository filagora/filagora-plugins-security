<?php

declare(strict_types=1);

use Filagora\PluginsSecurity\Analysis\Analyzers\StaticPhpAnalyzer;
use Filagora\PluginsSecurity\Enums\ScanSeverity;
use Filagora\PluginsSecurity\Enums\ScanTrigger;
use Filagora\PluginsSecurity\Services\Scanner;

/**
 * The rule ids the static checks raise for an archive holding these files.
 *
 * @param  array<string, string>  $files
 * @return list<string>
 */
function rulesFor(array $files): array
{
    useStaticAnalyzerOnly();

    return collect(app(Scanner::class)->scan(releaseWith($files, slug: 'p'.uniqid()), ScanTrigger::MANUAL)->findings)->pluck('rule_id')->sort()->values()->all();
}

it('flags a dangerous call', function (string $function, string $rule, ScanSeverity $severity) {
    useStaticAnalyzerOnly();

    $findings = app(Scanner::class)->scan(releaseWith(['a.php' => "<?php\n{$function}(\$x);\n"], slug: 'p'.uniqid()), ScanTrigger::MANUAL)->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]['rule_id'])->toBe($rule)
        ->and($findings[0]['severity'])->toBe($severity->value)
        ->and($findings[0]['line'])->toBe(2)
        ->and($findings[0]['file'])->toBe('a.php');
})->with([
    ['exec', 'exec-call', ScanSeverity::HIGH],
    ['shell_exec', 'shell-exec-call', ScanSeverity::HIGH],
    ['system', 'system-call', ScanSeverity::HIGH],
    ['passthru', 'passthru-call', ScanSeverity::HIGH],
    ['popen', 'popen-call', ScanSeverity::HIGH],
    ['proc_open', 'proc-open-call', ScanSeverity::HIGH],
    ['pcntl_exec', 'pcntl-exec-call', ScanSeverity::HIGH],
    ['assert', 'assert-call', ScanSeverity::MEDIUM],
    ['create_function', 'create-function-call', ScanSeverity::HIGH],
    ['dl', 'dl-call', ScanSeverity::HIGH],
    ['EVAL', 'eval-construct', ScanSeverity::HIGH],
]);

it('does not flag a call that is only mentioned', function (string $code) {
    expect(rulesFor(['a.php' => "<?php\n{$code}\n"]))->toBe([]);
})->with([
    'a comment' => '// system($x); exec($y);',
    'a doc comment' => '/** exec() and eval() */ echo 1;',
    'a string' => '$s = "system(1) and eval(2)";',
    'a method' => '$this->system($x); $obj->exec($y);',
    'a static method' => 'Shell::exec($x); Shell::system($y);',
    'a nullsafe method' => '$obj?->exec($x);',
    'a declaration' => 'namespace Legacy; function exec($x) { return 1; }',
    'a constant' => 'echo system;',
    'a longer name' => 'my_exec($x); execute($y); systematic($z);',
]);

it('flags each use of the backtick operator once', function () {
    expect(rulesFor(['a.php' => "<?php\n\$out = `ls -l`;\n\$more = `id`;\n"]))->toBe(['backtick-exec', 'backtick-exec']);
});

it('flags a syntax error with the first line of what php says', function () {
    $findings = (function () {
        useStaticAnalyzerOnly();

        return app(Scanner::class)->scan(releaseWith(['a.php' => "<?php\nfunction ( {\n"]), ScanTrigger::MANUAL)->findings;
    })();

    expect($findings)->toHaveCount(1)
        ->and($findings[0]['rule_id'])->toBe('php-syntax-error')
        ->and($findings[0]['severity'])->toBe('medium')
        ->and($findings[0]['title'])->toContain('syntax error')
        ->and($findings[0]['title'])->not->toContain('filagora-lint');
});

it('does not blame the file when the php binary to lint with is missing', function () {
    config(['filagora-plugins-security.analyzers.static_php.php_binary' => '/nonexistent/php']);

    expect(rulesFor(['a.php' => "<?php\necho 1;\n"]))->toBe([]);
});

it('flags a PHAR archive', function () {
    expect(rulesFor(['tools/build.phar' => 'x']))->toBe(['phar-archive']);
});

it('flags a PHP handler in an htaccess file', function (string $line) {
    expect(rulesFor(['.htaccess' => $line]))->toBe(['htaccess-php-handler']);
})->with(['php_value auto_prepend_file x.php', 'php_flag display_errors on', 'AddHandler application/x-httpd-php .jpg', 'SetHandler x', 'addtype application/x-httpd-php .png']);

it('ignores an htaccess file that sets no handler', function () {
    expect(rulesFor(['.htaccess' => "Options -Indexes\nDeny from all\n"]))->toBe([]);
});

it('flags a PHP file that starts like an image as critical', function (string $header) {
    $findings = (function () use ($header) {
        useStaticAnalyzerOnly();

        return app(Scanner::class)->scan(releaseWith(['pic.php' => $header."\n<?php echo 1;"]), ScanTrigger::MANUAL)->findings;
    })();

    expect(collect($findings)->firstWhere('rule_id', 'php-image-polyglot')['severity'])->toBe('critical');
})->with(['GIF89a', 'GIF87a', "\x89PNG\r\n\x1a\n", "\xFF\xD8\xFF\xE0"]);

it('does not read an image as a polyglot', function () {
    expect(rulesFor(['pic.gif' => "GIF89a\n<?php eval(\$x);"]))->toBe([]);
});

it('flags the e modifier of preg_replace', function (string $code) {
    expect(rulesFor(['a.php' => "<?php\n{$code}\n"]))->toContain('preg-replace-eval');
})->with([
    "preg_replace('/a/e', 'b', \$x);",
    "preg_replace(\"/a/ei\", 'b', \$x);",
    "preg_replace('/a' . 'e', 'b', \$x);",
]);

it('does not flag a plain preg_replace', function () {
    expect(rulesFor(['a.php' => "<?php\npreg_replace('/a/i', 'b', \$x);\n"]))->toBe([]);
});

it('flags a decoder feeding a dynamic call as an obfuscated payload', function (string $code) {
    expect(rulesFor(['a.php' => "<?php\n{$code}\n"]))->toContain('obfuscated-payload');
})->with([
    'eval(base64_decode($x));',
    '$f = "x"; $f(gzinflate($y));',
    'call_user_func(str_rot13($x));',
]);

it('does not flag a decoder on its own', function () {
    expect(rulesFor(['a.php' => "<?php\n\$data = base64_decode(\$x);\n"]))->toBe([]);
});

it('flags a file whose hash is on the known bad list as critical, and checks nothing else in it', function () {
    $content = "<?php\neval(\$x);\n";
    config(['filagora-plugins-security.analyzers.static_php.known_bad_sha256' => [strtoupper(hash('sha256', $content))]]);
    useStaticAnalyzerOnly();

    $findings = app(Scanner::class)->scan(releaseWith(['bad.php' => $content]), ScanTrigger::MANUAL)->findings;

    expect($findings)->toHaveCount(1)
        ->and($findings[0]['rule_id'])->toBe('known-bad-hash')
        ->and($findings[0]['severity'])->toBe('critical')
        ->and($findings[0]['snippet'])->toBe(hash('sha256', $content));
});

it('checks php files by any of its extensions', function (string $name) {
    expect(rulesFor([$name => "<?php\neval(\$x);\n"]))->toBe(['eval-construct']);
})->with(['a.php', 'a.PHP', 'a.php5', 'a.phtml', 'a.inc', 'a.php7']);

it('leaves other files alone', function () {
    expect(rulesFor(['a.txt' => 'eval($x); exec($y);', 'b.js' => 'eval(x)']))->toBe([]);
});

it('stops after the configured number of files', function () {
    config(['filagora-plugins-security.analyzers.static_php.max_files' => 2]);

    expect(rulesFor(['a.php' => '<?php eval($x);', 'b.php' => '<?php eval($x);', 'c.php' => '<?php eval($x);']))->toHaveCount(2);
});

it('gives the same fingerprint to the same finding in a later scan, and another for another file', function () {
    useStaticAnalyzerOnly();
    $one = app(Scanner::class)->scan(releaseWith(['a.php' => "<?php\neval(\$x);"], slug: 'one'), ScanTrigger::MANUAL)->findings[0]['fingerprint'];
    $again = app(Scanner::class)->scan(releaseWith(['a.php' => "<?php\n\n\neval(\$x);"], slug: 'two'), ScanTrigger::MANUAL)->findings[0]['fingerprint'];
    $other = app(Scanner::class)->scan(releaseWith(['b.php' => "<?php\neval(\$x);"], slug: 'three'), ScanTrigger::MANUAL)->findings[0]['fingerprint'];

    expect($again)->toBe($one)->and($other)->not->toBe($one)->and($one)->toHaveLength(32);
});

it('is off when switched off, and says so', function () {
    config(['filagora-plugins-security.analyzers.static_php.enabled' => false]);

    expect(app(StaticPhpAnalyzer::class)->isAvailable())->toBeFalse();
});
