import { Parser } from 'web-tree-sitter';

let initializationPromise;

/**
 * Share in-flight runtime initialization across all tree-sitter providers.
 * Concurrent cold-start calls to Parser.init() can create competing Wasm
 * runtimes; grammar loading and parser creation must wait for the same one.
 * @returns {Promise<void>} runtime readiness, or the initialization error
 */
export function initializeTreeSitter() {
	initializationPromise ??= Parser.init().catch(error => {
		initializationPromise = undefined;
		throw error;
	});
	return initializationPromise;
}
