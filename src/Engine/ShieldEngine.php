<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Engine;

use Ganadev\Shield\Core\Clock\ClockInterface;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Decision\Decision;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Decision\DecisionInput;
use Ganadev\Shield\Core\Decision\Verdict;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Persistence\EventRepositoryInterface;
use Ganadev\Shield\Core\Privacy\UriMasker;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\RuleMatch;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Core\Scoring\ScoreBreakdown;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

/**
 * Framework-agnostic request processing pipeline (spec section 5).
 *
 * The engine depends only on interfaces; no framework types are used.
 */
final class ShieldEngine
{
    public function __construct(
        private readonly ShieldConfig $config,
        private readonly Normalizer $normalizer,
        private readonly ThreatSignatureEngine $signatures,
        private readonly BehaviorDetector $behavior,
        private readonly RiskScorer $scorer,
        private readonly DecisionEngine $decisionEngine,
        private readonly BanPolicy $banPolicy,
        private readonly RiskDecay $riskDecay,
        private readonly EventRepositoryInterface $events,
        private readonly ClockInterface $clock,
        private readonly ?BanRepositoryInterface $bans = null,
        private readonly ?TrustedCookieInterface $trusted = null,
    ) {}

    /**
     * @param  array<string, mixed>  $options  request_id, trusted_cookie
     */
    public function inspect(RequestContext $request, BehaviorCounters $counters, array $options = []): EngineResult
    {
        $normalized = $this->normalizer->normalize($request, $this->config);
        $matches = $this->signatures->evaluate($normalized);
        $hasCritical = $this->signatures->hasCriticalMatch($matches);

        if ($this->isAllowlisted($request) && ! $hasCritical) {
            $this->recordEarlyExitEvent(
                $request,
                $normalized,
                new ScoreBreakdown(0, 0, 0, 0, 0, [], [], false),
                [],
                new Verdict(Decision::Allowed, Decision::Allowed, 'allowlist', 0),
                $options,
            );

            return new EngineResult(
                verdict: new Verdict(Decision::Allowed, Decision::Allowed, 'allowlist', 0),
                request: $request,
                normalized: $normalized,
                score: new ScoreBreakdown(0, 0, 0, 0, 0, [], [], false),
                matches: [],
                activeBan: null,
                trusted: false,
                infrastructureDegraded: false,
                allowlisted: true,
            );
        }

        $trusted = false;
        if ($this->trusted !== null && $this->config->trustedEnabled) {
            $cookie = $options['trusted_cookie'] ?? null;
            if (is_string($cookie) && $cookie !== '') {
                $trusted = $this->trusted->validate($cookie, $request);
            }
        }

        $degraded = false;
        $activeBan = $this->loadActiveBan($request->ip, $degraded);

        if ($degraded && $this->config->failMode === ShieldConfig::FAIL_CLOSED) {
            $this->recordEarlyExitEvent(
                $request,
                $normalized,
                new ScoreBreakdown(0, 0, 0, 0, 99, [], [], false),
                $matches,
                new Verdict(Decision::BlockRequest, Decision::BlockRequest, 'fail_closed', 99),
                $options,
            );

            return new EngineResult(
                verdict: new Verdict(Decision::BlockRequest, Decision::BlockRequest, 'fail_closed', 99),
                request: $request,
                normalized: $normalized,
                score: new ScoreBreakdown(0, 0, 0, 0, 99, [], [], false),
                matches: $matches,
                activeBan: null,
                trusted: $trusted,
                infrastructureDegraded: true,
            );
        }

        $offenseCount = $activeBan === null ? 0 : $this->riskDecay->decayOffenseCount(
            $activeBan->offenseCount,
            $activeBan->lastSeenAt,
            $this->clock->now(),
        );

        $behaviorReport = $this->behavior->evaluate($request, $normalized, $counters, $this->config);
        $breakdown = $this->scorer->score($matches, $behaviorReport, $offenseCount, 0, $this->config);

        $verdict = $this->decisionEngine->decide(new DecisionInput(
            score: $breakdown,
            activeBan: $activeBan,
            trusted: $trusted,
            thresholdChallenge: $this->config->thresholdChallenge,
            thresholdBan: $this->config->thresholdBan,
            thresholdStrongBan: $this->config->thresholdStrongBan,
            mode: $this->config->mode,
        ));

        if ($this->config->botMode === ShieldConfig::BOT_CHALLENGE
            && $behaviorReport->has(BehaviorDetector::SIGNAL_UNVERIFIED_CRAWLER_CLAIM)
            && ! $verdict->decision->isTerminal()) {
            $verdict = new Verdict(
                intended: Decision::Challenge,
                decision: Decision::Challenge,
                reason: 'unverified_crawler_claim_'.($behaviorReport->knownCrawler ?? 'unknown'),
                score: $breakdown->total,
                matchedRuleIds: $breakdown->matchedRuleIds,
                behaviorSignals: $breakdown->behaviorSignals,
            );
        } elseif ($this->config->botMode === ShieldConfig::BOT_OBSERVE
            && $activeBan === null
            && $breakdown->matchedRuleIds === []
            && $behaviorReport->has(BehaviorDetector::SIGNAL_UNVERIFIED_CRAWLER_CLAIM)
            && $verdict->decision->isTerminal()) {
            // In observe mode an unverified crawler claim may be scored, but it
            // must never escalate on its own. Crawlers that fail DNS
            // verification (broken reverse DNS, sandboxed deployments) would
            // otherwise be challenged or banned purely by burst counters, which
            // silently removes them from search results. Only a signature match
            // or an already active ban may still enforce here, hence the guard
            // on matchedRuleIds and on the absence of an active ban.
            $verdict = new Verdict(
                intended: $verdict->intended,
                decision: Decision::Observe,
                reason: 'crawler_behavior_exempt_'.($behaviorReport->knownCrawler ?? 'unknown'),
                score: $breakdown->total,
                matchedRuleIds: $breakdown->matchedRuleIds,
                behaviorSignals: $breakdown->behaviorSignals,
            );
        }

        $this->persist($request, $normalized, $breakdown, $matches, $verdict, $activeBan, $options);

        return new EngineResult(
            verdict: $verdict,
            request: $request,
            normalized: $normalized,
            score: $breakdown,
            matches: $matches,
            activeBan: $activeBan,
            trusted: $trusted,
            infrastructureDegraded: $degraded,
        );
    }

    public function releaseBan(string $ip, string $reason, ?string $actor = null): bool
    {
        if ($this->bans === null) {
            return false;
        }

        $ban = $this->bans->findActiveByIp($ip);
        if ($ban === null) {
            return false;
        }

        $this->bans->release($ban, $reason, $actor);

        return true;
    }

    /**
     * Records a successful challenge: releases the ban and stamps the
     * challenge_passed_at timestamp (history is never deleted).
     */
    public function markChallengePassed(string $ip): bool
    {
        if ($this->bans === null) {
            return false;
        }

        $ban = $this->bans->findActiveByIp($ip);
        if ($ban === null) {
            return false;
        }

        $this->bans->markChallengePassed($ban, $this->clock->now());

        return true;
    }

    public function issueTrustedCookie(RequestContext $request): string
    {
        if ($this->trusted === null) {
            return '';
        }

        return $this->trusted->issue($request, $this->config->trustedTtlMinutes);
    }

    /**
     * @return non-empty-string
     */
    public function trustedCookieName(): string
    {
        return $this->trusted?->name() ?? 'shield_trusted';
    }

    /**
     * @param  list<RuleMatch>  $matches
     * @param  array<string, mixed>  $options
     */
    private function persist(
        RequestContext $request,
        mixed $normalized,
        ScoreBreakdown $breakdown,
        array $matches,
        Verdict $verdict,
        ?BanRecord $activeBan,
        array $options = [],
    ): void {
        if ($this->shouldLogDecision($verdict)) {
            $this->recordEvent($request, $normalized, $breakdown, $matches, $verdict, $options);
        }

        if ($verdict->blocked()) {
            $this->enforceBan($request, $breakdown, $activeBan);
        } elseif ($activeBan !== null && $verdict->decision === Decision::Allowed) {
            $this->touchBan($activeBan);
        }
    }

    /**
     * Applies `logging.level`. Recording every request made the event table grow
     * without bound on busy sites and buried the rows an operator actually needs,
     * so the default only keeps decisions that are not a plain ALLOW.
     */
    private function shouldLogDecision(Verdict $verdict): bool
    {
        return match ($this->config->loggingLevel) {
            ShieldConfig::LOG_ALL => true,
            ShieldConfig::LOG_BLOCKED => $verdict->decision->isBlocking(),
            default => $verdict->decision !== Decision::Allowed,
        };
    }

    /**
     * Records the allowlist and fail-closed short circuits, which are security
     * relevant decisions that would otherwise leave no audit trail at all.
     *
     * @param  list<RuleMatch>  $matches
     * @param  array<string, mixed>  $options
     */
    private function recordEarlyExitEvent(
        RequestContext $request,
        mixed $normalized,
        ScoreBreakdown $breakdown,
        array $matches,
        Verdict $verdict,
        array $options,
    ): void {
        if ($this->config->logBypassEvents) {
            $this->recordEvent($request, $normalized, $breakdown, $matches, $verdict, $options);
        }
    }

    /**
     * @param  list<RuleMatch>  $matches
     * @param  array<string, mixed>  $options
     */
    private function recordEvent(
        RequestContext $request,
        mixed $normalized,
        ScoreBreakdown $breakdown,
        array $matches,
        Verdict $verdict,
        array $options = [],
    ): void {
        $masker = new UriMasker;
        $sensitive = $this->config->sensitiveQueryParameters;
        $requestId = $options['request_id'] ?? null;

        $event = SecurityEvent::create([
            'ip' => $request->ip,
            'host' => $request->host,
            'method' => $request->method,
            'raw_uri' => $masker->mask($request->rawUri, $sensitive),
            'normalized_uri' => $masker->mask($normalized->normalizedUri, $sensitive),
            'rule_id' => $verdict->ruleId,
            'category' => $matches[0] ?? null ? $matches[0]->rule->category : null,
            'severity' => $matches[0] ?? null ? $matches[0]->rule->severity->value : 'low',
            'score_delta' => $breakdown->total,
            'decision' => $verdict->decision->value,
            'intended_decision' => $verdict->intended->value,
            'user_agent' => $request->userAgent(),
            'referer' => $request->referer() !== '' ? $request->referer() : null,
            'request_id' => is_string($requestId) && $requestId !== '' ? $requestId : null,
            'rule_version' => $this->config->ruleVersion,
            'created_at' => $this->clock->now(),
        ]);

        $this->events->record($event);
    }

    private function enforceBan(RequestContext $request, ScoreBreakdown $breakdown, ?BanRecord $activeBan): void
    {
        if ($this->bans === null) {
            return;
        }

        try {
            $now = $this->clock->now();
            $previous = $activeBan ?? $this->bans->findLatestByIp($request->ip);
            $offenseCount = $this->banPolicy->nextOffenseCount($previous);
            $durationMinutes = $this->banPolicy->durationFor($offenseCount, $this->config->banDurations);

            $metadata = ['manual_review' => $this->banPolicy->requiresManualReview($offenseCount)];

            $record = new BanRecord(
                id: null,
                ipAddress: $request->ip,
                status: BanStatus::Active,
                reason: $breakdown->matchedRuleIds[0] ?? 'score_ban',
                lastRuleId: $breakdown->matchedRuleIds[0] ?? null,
                riskScore: $breakdown->total,
                violationCount: $breakdown->matchedRuleIds !== [] ? $breakdown->total : 0,
                offenseCount: $offenseCount,
                bannedAt: $now,
                expiresAt: $now->modify("+{$durationMinutes} minutes"),
                releasedAt: null,
                challengePassedAt: null,
                lastSeenAt: $now,
                metadata: $metadata,
            );

            $this->bans->createBan($record);
        } catch (\Throwable) {
            // A stateless critical block must still take effect even if the
            // ban store is unavailable (fail-open persistence).
        }
    }

    private function touchBan(BanRecord $ban): void
    {
        if ($this->bans === null) {
            return;
        }

        $this->bans->touchLastSeen($ban, $this->clock->now());
    }

    private function loadActiveBan(string $ip, bool &$degraded): ?BanRecord
    {
        $degraded = false;
        if ($this->bans === null) {
            return null;
        }

        try {
            return $this->bans->findActiveByIp($ip);
        } catch (\Throwable) {
            $degraded = true;
            if ($this->config->failMode === ShieldConfig::FAIL_CLOSED) {
                return new BanRecord(
                    id: null,
                    ipAddress: $ip,
                    status: BanStatus::Active,
                    reason: 'fail_closed',
                    lastRuleId: null,
                    riskScore: 99,
                    violationCount: 0,
                    offenseCount: 1,
                    bannedAt: $this->clock->now(),
                    expiresAt: $this->clock->now()->modify('+1 hour'),
                    releasedAt: null,
                    challengePassedAt: null,
                    lastSeenAt: $this->clock->now(),
                );
            }

            return null;
        }
    }

    private function isAllowlisted(RequestContext $request): bool
    {
        $allowlist = $this->config->allowlist;

        if (in_array($request->host, $allowlist['hosts'], true)) {
            return true;
        }

        if (in_array($request->ip, $allowlist['ips'], true)) {
            return true;
        }

        foreach ($allowlist['paths'] as $path) {
            if (str_starts_with($request->rawPath, $path)) {
                return true;
            }
        }

        return false;
    }
}
