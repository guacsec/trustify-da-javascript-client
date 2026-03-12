import { fileURLToPath } from 'url';

import { Language, Parser, Query } from 'web-tree-sitter';

const wasmPath = fileURLToPath(import.meta.resolve('tree-sitter-requirements/tree-sitter-requirements.wasm'));

async function init() {
	await Parser.init();
	return await Language.load(wasmPath);
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
