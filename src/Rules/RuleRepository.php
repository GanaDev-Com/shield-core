<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules;

use Ganadev\Shield\Core\Exceptions\InvalidConfigException;

final class RuleRepository
{
    /**
     * @param  array<string, Rule>  $rules
     */
    public function __construct(
        private readonly array $rules = [],
    ) {}

    /**
     * @param  array<int, array<string, mixed>>  $rules
     */
    public static function fromArray(array $rules): self
    {
        $map = [];
        foreach ($rules as $data) {
            $rule = Rule::fromArray($data);
            $map[$rule->id] = $rule;
        }

        return new self($map);
    }

    /**
     * @param  list<Rule>  $rules
     */
    public static function fromRules(array $rules): self
    {
        $map = [];
        foreach ($rules as $rule) {
            $map[$rule->id] = $rule;
        }

        return new self($map);
    }

    /**
     * @return list<Rule>
     */
    public function all(): array
    {
        return array_values($this->rules);
    }

    public function get(string $id): ?Rule
    {
        return $this->rules[$id] ?? null;
    }

    /**
     * @return list<Rule>
     */
    public function active(): array
    {
        return array_values(array_filter(
            $this->rules,
            static fn (Rule $rule): bool => $rule->enabled,
        ));
    }

    public function withDisabled(string $id): self
    {
        $rule = $this->get($id);
        if ($rule === null) {
            throw new InvalidConfigException("Unknown rule: {$id}");
        }

        $clone = $this->rules;
        $clone[$id] = new Rule(
            id: $rule->id,
            category: $rule->category,
            matcher: $rule->matcher,
            value: $rule->value,
            severity: $rule->severity,
            score: $rule->score,
            immediateBan: $rule->immediateBan,
            enabled: false,
        );

        return new self($clone);
    }

    public function count(): int
    {
        return count($this->rules);
    }
}
