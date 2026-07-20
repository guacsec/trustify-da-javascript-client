import { readFile } from 'node:fs/promises';

import { Language, Parser, Query } from 'web-tree-sitter';

const wasmUrl = new URL('./tree-sitter-containerfile.wasm', import.meta.url);

async function init() {
	await Parser.init();
	const wasmBytes = new Uint8Array(await readFile(wasmUrl));
	return await Language.load(wasmBytes);
}

export async function getParser() {
	const language = await init();
	return new Parser().setLanguage(language);
}

export async function getFromQuery() {
	const language = await init();
	return new Query(language, '(from_instruction (image_spec) @image)');
}

export async function getArgQuery() {
	const language = await init();
	return new Query(language, '(arg_instruction (arg_pair name: (_) @name default: (_) @default))');
}
