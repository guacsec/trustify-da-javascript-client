import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { expect } from 'chai';

const runner = fileURLToPath(new URL('../utils/tree_sitter_initialization.mjs', import.meta.url));

suite('shared tree-sitter runtime initialization', () => {
	/** Verifies overlapping provider startup initializes one runtime and produces usable parsers and queries. */
	test('concurrent requirements, Go and Containerfile consumers share cold-start initialization', () => {
		const result = JSON.parse(execFileSync(process.execPath, [runner], { encoding: 'utf8', timeout: 10000 }));

		expect(result.coldStartCalls, 'overlapping runtime initializations').to.equal(1);
		expect(result.initializationCalls).to.equal(1);
		expect(result.captures).to.deep.equal([['blinker'], ['example.com/lib'], ['alpine:3.19']]);
	}).timeout(15000);

	/** Verifies initialization errors reach all waiting consumers and do not permanently poison later requests. */
	test('failed initialization propagates to all consumers and allows a later retry', () => {
		const result = JSON.parse(execFileSync(process.execPath, [runner, 'retry'], { encoding: 'utf8', timeout: 10000 }));

		expect(result.errorsPropagated).to.equal(true);
		expect(result.initializationCalls).to.equal(2);
		expect(result.captures).to.deep.equal([['blinker'], ['example.com/lib'], ['alpine:3.19']]);
	}).timeout(15000);
});
