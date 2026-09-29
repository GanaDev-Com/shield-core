<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules;

use Ganadev\Shield\Core\Exceptions\InvalidConfigException;

final class Rule
{
    public function __construct(
        public readonly string $id,
        public readonly string $category,
        public readonly MatcherType $matcher,
        public readonly string $value,
        public readonly RuleSeverity $severity,
        public readonly int $score,
        public readonly bool $immediateBan,
        public readonly bool $enabled = true,
    ) {
        if ($this->id === '') {
            throw new InvalidConfigException('Rule id must not be empty.');
        }
        if ($this->score < 0) {
            throw new InvalidConfigException("Rule {$this->id} score must be non-negative.");
        }
        if ($this->matcher === MatcherType::Regex) {
            $this->assertSafeRegex($this->value);
        }
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $matcher = $data['matcher'] instanceof MatcherType
            ? $data['matcher']
            : MatcherType::from((string) $data['matcher']);

        $severity = $data['severity'] instanceof RuleSeverity
            ? $data['severity']
            : RuleSeverity::from((string) $data['severity']);

        return new self(
            id: (string) $data['id'],
            category: (string) ($data['category'] ?? 'general'),
            matcher: $matcher,
            value: (string) $data['value'],
            severity: $severity,
            score: (int) ($data['score'] ?? self::defaultScoreFor($severity)),
            immediateBan: (bool) ($data['immediate_ban'] ?? false),
            enabled: (bool) ($data['enabled'] ?? true),
        );
    }

    private static function defaultScoreFor(RuleSeverity $severity): int
    {
        return match ($severity) {
            RuleSeverity::Critical => 30,
            RuleSeverity::High => 20,
            RuleSeverity::Medium => 12,
            RuleSeverity::Low => 4,
        };
    }

    /**
     * Guards against catastrophic backtracking patterns and throws on obvious
     * ReDoS-prone expressions.
     */
    private function assertSafeRegex(string $pattern): void
    {
        if ($pattern === '') {
            throw new InvalidConfigException('Regex rule value must not be empty.');
        }

        $full = '~'.$pattern.'~i';
        $payload = str_repeat('A', 64).'!';

        $start = hrtime(true);
        $result = @preg_match($full, $payload);
        $elapsed = (hrtime(true) - $start) / 1e6;

        if ($result === false) {
            throw new InvalidConfigException("Regex rule failed to compile: {$this->id}");
        }

        if ($elapsed > 50.0) {
            throw new InvalidConfigException("Regex rule may be ReDoS-prone: {$this->id}");
        }
    }
}
