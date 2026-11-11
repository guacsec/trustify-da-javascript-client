import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { TextDecoder } from 'node:util';

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
	return new Query(language, '((requirement (package) @name) @req . (comment) @comment (#match? @comment "^#[\\t ]*(exhortignore|trustify-da-ignore)(?![\\w-])"))');
}

export async function getPinnedVersionQuery() {
	const language = await init();
	return new Query(language, '(version_spec (version_cmp) @cmp (version) @version (#eq? @cmp "=="))');
}

/**
 * Decode raw requirements-file bytes into text, honouring an optional BOM.
 * Windows PowerShell 5.1 redirection (`pip freeze > requirements.txt`) emits
 * UTF-16LE with a BOM; decoding those bytes as UTF-8 interleaves NUL characters
 * and makes the tree-sitter query recover bogus package names.
 * `TextDecoder` strips a leading BOM from its output by default, so the decoded
 * text never contains the byte-order mark itself.
 * @param {Buffer|Uint8Array} bytes - raw file content
 * @returns {string} decoded text with the BOM removed
 */
export function decodeRequirementsFileContent(bytes) {
	const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
	if (buffer[0] === 0xff && buffer[1] === 0xfe) {
		return new TextDecoder('utf-16le').decode(buffer);
	}
	if (buffer[0] === 0xfe && buffer[1] === 0xff) {
		return new TextDecoder('utf-16be').decode(buffer);
	}
	if (buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
		return new TextDecoder('utf-8').decode(buffer);
	}
	return buffer.toString('utf8');
}

/**
 * Read a requirements file and return its decoded text, so every consumer of a
 * requirements manifest (dependency extraction and ignore handling) sees the
 * same content regardless of the encoding the file was saved with.
 * @param {string} filePath - path to a requirements manifest
 * @returns {string} decoded manifest text
 */
export function readRequirementsFile(filePath) {
	return decodeRequirementsFileContent(readFileSync(filePath));
}
