import { readFile } from 'node:fs/promises';

import { Language, Parser, Query } from 'web-tree-sitter';

const wasmUrl = new URL('./tree-sitter-gomod.wasm', import.meta.url);

async function init() {
	await Parser.init();
	const wasmBytes = new Uint8Array(await readFile(wasmUrl));
	return await Language.load(wasmBytes);
}

export async function getParser() {
	const language = await init();
	return new Parser().setLanguage(language);
}

export async function getRequireQuery() {
	const language = await init();
	return new Query(language, '(require_spec (module_path) @name (version) @version) @spec');
}
