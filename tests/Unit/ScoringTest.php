<?php

declare(strict_types=1);

it('accumulates signature and behavior scores into a breakdown', function () {
    $score = breakdown(signature: 30, behavior: 12);

    expect($score->signatureScore)->toBe(30);
    expect($score->behaviorScore)->toBe(12);
    expect($score->total)->toBe(42);
});

it('applies escalation multiplier for prior offenses', function () {
    $score = breakdown(signature: 20, offense: 2);

    expect($score->escalationScore)->toBe(10);
    expect($score->total)->toBe(30);
});

it('caps escalation at five prior offenses', function () {
    $score = breakdown(signature: 10, offense: 10);

    expect($score->escalationScore)->toBe(25);
});

it('adds challenge penalty without resetting history', function () {
    $score = breakdown(signature: 10, challengePenalty: 10);

    expect($score->challengePenalty)->toBe(10);
    expect($score->total)->toBe(20);
});

it('does not escalate when there is no current violation', function () {
    $score = breakdown(signature: 0, behavior: 0, offense: 3);

    expect($score->escalationScore)->toBe(0);
});

it('marks critical matches in the breakdown', function () {
    $score = breakdown(signature: 30, critical: true);

    expect($score->hasCritical)->toBeTrue();
});
