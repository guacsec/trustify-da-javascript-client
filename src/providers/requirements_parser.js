import { readFile } from 'node:fs/promises';

import { Language, Parser, Query } from 'web-tree-sitter';

const wasmUrl = new URL('./tree-sitter-requirements.wasm', import.meta.url);

async function init() {
	await Parser.init();
	const wasmBytes = new Uint8Array(await readFile(wasmUrl));
	return await Language.load(wasmBytes);
}

export async function getParser() {
	const language = await init();
	return new Parser().setLanguage(language);
}

export async function getRequirementQuery() {
	const language = await init();
	return new Query(language, '(requirement (package) @name) @req');
}

export async function getIgnoreQuery() {
	const language = await init();
	return new Query(language, '((requirement (package) @name) @req . (comment) @comment (#match? @comment "^#[\\t ]*exhortignore"))');
}

export async function getPinnedVersionQuery() {
	const language = await init();
	return new Query(language, '(version_spec (version_cmp) @cmp (version) @version (#eq? @cmp "=="))');
}
