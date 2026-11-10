import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';

import { Language, Parser, Query } from 'web-tree-sitter';

const wasmUrl = new URL('./tree-sitter-requirements.wasm', import.meta.url);

const UTF8_BOM = [0xEF, 0xBB, 0xBF];
const UTF16LE_BOM = [0xFF, 0xFE];
const UTF16BE_BOM = [0xFE, 0xFF];

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
 * Check whether raw bytes start with the given byte-order mark.
 * @param {Buffer} buffer - raw file content
 * @param {number[]} prefix - BOM bytes to look for
 * @returns {boolean} true when the buffer starts with the BOM
 */
function hasPrefix(buffer, prefix) {
	return buffer.length >= prefix.length && prefix.every((byte, index) => buffer[index] === byte);
}

/**
 * Decode UTF-16BE bytes (already stripped of the BOM) by swapping byte pairs
 * into little-endian order, which Node.js can decode natively.
 * @param {Buffer} bytes - UTF-16BE payload without the BOM
 * @returns {string} decoded text
 */
function decodeUtf16be(bytes) {
	const evenLength = bytes.length - (bytes.length % 2);
	return Buffer.from(bytes.subarray(0, evenLength)).swap16().toString('utf16le');
}

/**
 * Decode raw requirements-file bytes into text, honouring an optional BOM.
 * Windows PowerShell 5.1 redirection (`pip freeze > requirements.txt`) emits
 * UTF-16LE with a BOM; decoding those bytes as UTF-8 interleaves NUL characters
 * and makes the tree-sitter query recover bogus package names.
 * @param {Buffer|Uint8Array} bytes - raw file content
 * @returns {string} decoded text with the BOM removed
 */
export function decodeRequirementsFileContent(bytes) {
	const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
	if (hasPrefix(buffer, UTF16LE_BOM)) {
		return buffer.subarray(UTF16LE_BOM.length).toString('utf16le');
	}
	if (hasPrefix(buffer, UTF16BE_BOM)) {
		return decodeUtf16be(buffer.subarray(UTF16BE_BOM.length));
	}
	if (hasPrefix(buffer, UTF8_BOM)) {
		return buffer.subarray(UTF8_BOM.length).toString('utf8');
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
