// Copyright 2026 Vikrant Rathore and Ronak Rathore. LGPL-3.0; see LICENSE.
// Scripted explanatory timing, not a workload, solver or measurement of visitor latency.
export const firstTimes = {
    arrival: 0, challenge: 3, work: 6, proof: 11, verification: 14,
    retry: 17, checks: 20, forward: 23, end: 26,
};
export const returnTimes = { arrival: 0, checks: 3, forward: 6, end: 9 };

export const journeys = {
    first: {
        label: 'First visit', duration: firstTimes.end,
        steps: [
            [firstTimes.arrival, 'A request arrives', 'The browser sends a request through your HTTPS ingress.'],
            [firstTimes.challenge, 'This route asks for work', 'Sibuna returns a challenge to the client.'],
            [firstTimes.work, 'The client creates a proof',
                'Sequential work happens in the browser. Later steps depend on earlier results.'],
            [firstTimes.proof, 'The proof returns', 'The client submits its proof to Sibuna.'],
            [firstTimes.verification, 'Check the proof. Issue a session.',
                'Checking the proof is designed to take less computation than creating it.'],
            [firstTimes.retry, 'Try again with a session', 'The browser retries the request with its session.'],
            [firstTimes.checks, 'The checks still apply',
                'A session does not bypass applicable inspection, deny rules or rate limits.'],
            [firstTimes.forward, 'The request reaches your app', 'This admitted request is forwarded to the application.'],
        ],
    },
    session: {
        label: 'With a session', duration: returnTimes.end,
        steps: [
            [returnTimes.arrival, 'Return with a session', 'The client sends another request with its signed session.'],
            [returnTimes.checks, 'Check access again',
                'Sibuna checks the session and applicable rules. A new puzzle is not needed here.'],
            [returnTimes.forward, 'The request reaches your app', 'The admitted request is forwarded to the application.'],
        ],
    },
    blocked: {
        label: 'Blocked by a rule', duration: returnTimes.end,
        steps: [
            [returnTimes.arrival, 'A request arrives', 'This request also reaches Sibuna through your ingress.'],
            [returnTimes.checks, 'A deny rule matches', 'A configured rule refuses this request, even with a valid session.'],
            [returnTimes.forward, 'The request stops here', 'Sibuna does not forward this refused request to the application.'],
        ],
    },
};

export const order = Object.keys(journeys);

export function frameAt(name, time) {
    const journey = journeys[name];
    const elapsed = Math.max(0, Math.min(journey.duration, time));
    let index = 0;
    for (let i = 1; i < journey.steps.length; i++) {
        if (elapsed >= journey.steps[i][0]) index = i;
    }
    const step = journey.steps[index];
    return { name, elapsed, index, title: step[1], text: step[2],
        progress: elapsed / journey.duration, steps: journey.steps.length };
}

export function nextStep(name, time) {
    const journey = journeys[name];
    return journey.steps.find(step => step[0] > time + 0.01)?.[0] ?? 0;
}

export function fraction(time, start, end) {
    return Math.max(0, Math.min(1, (time - start) / (end - start)));
}
