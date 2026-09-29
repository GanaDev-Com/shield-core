<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules;

/**
 * Default threat rule set (spec section 23).
 *
 * Rules are pure data so a project can extend, tune or disable any of them
 * without editing vendor code. Critical rules are safe-by-default and should
 * only be disabled with an explicit decision.
 */
final class DefaultRules
{
    /**
     * @return array<int, array<string, mixed>>
     */
    public static function definitions(): array
    {
        return [
            [
                'id' => 'sensitive.env',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => '/.env',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.env.decoded',
                'category' => 'sensitive_file',
                'matcher' => 'decoded_contains',
                'value' => '.env',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.git',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => '/.git',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.git.credentials',
                'category' => 'credential',
                'matcher' => 'contains',
                'value' => '.git-credentials',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.git.config',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => '.gitconfig',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.aws',
                'category' => 'credential',
                'matcher' => 'prefix',
                'value' => '/.aws/',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.aws.credentials',
                'category' => 'credential',
                'matcher' => 'contains',
                'value' => 'aws/credentials',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.wpconfig',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => 'wp-config',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.joomla',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => 'configuration.php',
                'severity' => 'high',
                'score' => 20,
                'immediate_ban' => true,
            ],
            [
                'id' => 'sensitive.composer',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => 'composer.json',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'sensitive.composer.lock',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => 'composer.lock',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'sensitive.phpunit',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => 'phpunit',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'backup.php',
                'category' => 'backup_file',
                'matcher' => 'regex',
                'value' => '\.php\.(bak|old|save|swp|tmp|orig|copy|zip|tar|gz)$',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'traversal.proc',
                'category' => 'path_traversal',
                'matcher' => 'decoded_contains',
                'value' => '/proc/self/environ',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'traversal.etcpasswd',
                'category' => 'path_traversal',
                'matcher' => 'decoded_contains',
                'value' => '/etc/passwd',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'traversal.generic',
                'category' => 'path_traversal',
                'matcher' => 'decoded_contains',
                'value' => '../',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'traversal.backslash',
                'category' => 'path_traversal',
                'matcher' => 'decoded_contains',
                'value' => '..\\',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'rce.phpinput',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'php://input',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'rce.prepend',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'auto_prepend_file',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'debug.wordpress',
                'category' => 'sensitive_file',
                'matcher' => 'contains',
                'value' => '/wp-content/debug.log',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'honeypot.phpinfo',
                'category' => 'honeypot',
                'matcher' => 'prefix',
                'value' => '/phpinfo.php',
                'severity' => 'high',
                'score' => 20,
                'immediate_ban' => true,
            ],
            [
                'id' => 'honeypot.adminbackup',
                'category' => 'honeypot',
                'matcher' => 'prefix',
                'value' => '/admin-backup',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'honeypot.debugconfig',
                'category' => 'honeypot',
                'matcher' => 'prefix',
                'value' => '/debug-config',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'payload.query.traversal',
                'category' => 'path_traversal',
                'matcher' => 'query_contains',
                'value' => '../../',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'sensitive.env.variants',
                'category' => 'sensitive_file',
                'matcher' => 'prefix',
                'value' => '/env.',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'cms.xmlrpc',
                'category' => 'cms_probe',
                'matcher' => 'prefix',
                'value' => '/xmlrpc.php',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'exec.static_dirs',
                'category' => 'code_execution',
                'matcher' => 'regex',
                'value' => '^/(.*/)?(images|media|uploads|cache|cgi-bin|blogs|logs|class|wp-admin/(js|css|images|includes))/[^/]*\.php$',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'exec.uploads_php',
                'category' => 'code_execution',
                'matcher' => 'regex',
                'value' => '^/.*/(wp-content/)?uploads/.*\.php$',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'exec.hidden_php',
                'category' => 'code_execution',
                'matcher' => 'regex',
                'value' => '^/\.[^/]+/.*\.php$',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'rce.call_user_func',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'call_user_func',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'rce.thinkphp',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'think\\app',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'rce.thinkphp.invokefunction',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'invokefunction',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'rce.ini_directives',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'allow_url_include',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'rce.ini_disable_functions',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'disable_functions',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'rce.system_calls',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'shell_exec',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'rce.system_calls.passthru',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'passthru',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'rce.system_calls.proc_open',
                'category' => 'rce_probe',
                'matcher' => 'decoded_contains',
                'value' => 'proc_open',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
        ];
    }

    /**
     * Optional WordPress-specific rules (plugin CVEs etc.). Enabled via
     * `shield.rules.packs.wordpress`. Off by default to avoid false positives
     * on non-WordPress applications.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function wordpressDefinitions(): array
    {
        return [
            [
                'id' => 'wp.gravitysmtp',
                'category' => 'cms_plugin',
                'matcher' => 'prefix',
                'value' => '/wp-json/gravitysmtp/',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'wp.litespeed',
                'category' => 'cms_plugin',
                'matcher' => 'prefix',
                'value' => '/wp-content/plugins/litespeed-cache/',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'wp.litespeed.debug',
                'category' => 'cms_plugin',
                'matcher' => 'query_contains',
                'value' => 'litespeed_debug',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'wp.admin_ajax',
                'category' => 'cms_probe',
                'matcher' => 'prefix',
                'value' => '/wp-admin/admin-ajax.php',
                'severity' => 'medium',
                'score' => 8,
            ],
            [
                'id' => 'wp.php.plugins_deep',
                'category' => 'cms_plugin',
                'matcher' => 'regex',
                'value' => 'plugins/plugins/.*\.php$',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'wp.php.plugin_risk_files',
                'category' => 'cms_plugin',
                'matcher' => 'regex',
                'value' => 'plugins/[^/]+/(cache|up|shell|cmd)\.php$',
                'severity' => 'high',
                'score' => 20,
            ],
        ];
    }

    /**
     * Optional SQLi/XSS/LFI/command-injection payload rules. Enabled via
     * `shield.rules.packs.injection` (default on). High-confidence patterns
     * only: SQLi/critical RCE score high and can temp-ban, XSS/LFI stay in the
     * challenge band to avoid blocking legitimate users on accidental matches.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function injectionDefinitions(): array
    {
        return [
            // SQL injection (body + query).
            [
                'id' => 'payload.sqli.union',
                'category' => 'sql_injection',
                'matcher' => 'body_regex',
                'value' => '\bunion\b\s+(all\s+)?select\b',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'payload.sqli.union.query',
                'category' => 'sql_injection',
                'matcher' => 'regex',
                'value' => '\bunion\b\s+(all\s+)?select\b',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'payload.sqli.time',
                'category' => 'sql_injection',
                'matcher' => 'body_regex',
                'value' => '\b(sleep|pg_sleep|benchmark)\s*\(\s*\d',
                'severity' => 'high',
                'score' => 20,
            ],
            [
                'id' => 'payload.sqli.error',
                'category' => 'sql_injection',
                'matcher' => 'body_regex',
                'value' => '\b(extractvalue|updatexml|gtid_subset|geometrycollection)\s*\(',
                'severity' => 'high',
                'score' => 20,
            ],

            // Cross-site scripting (medium -> challenge band to limit FPs).
            [
                'id' => 'payload.xss.script',
                'category' => 'xss',
                'matcher' => 'body_regex',
                'value' => '<\s*script\b',
                'severity' => 'medium',
                'score' => 12,
            ],
            [
                'id' => 'payload.xss.script.query',
                'category' => 'xss',
                'matcher' => 'regex',
                'value' => '<\s*script\b',
                'severity' => 'medium',
                'score' => 12,
            ],
            [
                'id' => 'payload.xss.handler',
                'category' => 'xss',
                'matcher' => 'body_regex',
                'value' => '\bon(load|error|click|mouseover)\s*=',
                'severity' => 'medium',
                'score' => 12,
            ],
            [
                'id' => 'payload.xss.javascript',
                'category' => 'xss',
                'matcher' => 'body_regex',
                'value' => '\bjavascript\s*:',
                'severity' => 'medium',
                'score' => 12,
            ],
            [
                'id' => 'payload.xss.svg',
                'category' => 'xss',
                'matcher' => 'body_regex',
                'value' => '<svg[^>]*\bonload',
                'severity' => 'medium',
                'score' => 12,
            ],

            // Local file inclusion / data exfiltration.
            [
                'id' => 'payload.lfi.file',
                'category' => 'lfi',
                'matcher' => 'body_contains',
                'value' => 'file://',
                'severity' => 'medium',
                'score' => 12,
            ],
            [
                'id' => 'payload.lfi.data',
                'category' => 'lfi',
                'matcher' => 'body_contains',
                'value' => 'data://',
                'severity' => 'medium',
                'score' => 12,
            ],
            [
                'id' => 'payload.lfi.phpscheme',
                'category' => 'rce_probe',
                'matcher' => 'body_contains',
                'value' => 'php://input',
                'severity' => 'critical',
                'score' => 30,
                'immediate_ban' => true,
            ],
            [
                'id' => 'payload.rce.base64',
                'category' => 'code_execution',
                'matcher' => 'body_regex',
                'value' => '\b(base64_encode|base64_decode|gzuncompress|eval|assert)\s*\(',
                'severity' => 'medium',
                'score' => 12,
            ],

            // Command injection.
            [
                'id' => 'payload.cmd.invoke',
                'category' => 'command_injection',
                'matcher' => 'body_regex',
                'value' => '\b(system|exec|popen|proc_open|passthru|shell_exec)\s*\(',
                'severity' => 'high',
                'score' => 20,
            ],
        ];
    }

    public static function repository(): RuleRepository
    {
        return RuleRepository::fromArray(self::definitions());
    }
}
