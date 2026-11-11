import { Parser } from 'web-tree-sitter';

import * as containerfile from '../../src/providers/containerfile_parser.js';
import * as gomod from '../../src/providers/gomod_parser.js';
import * as requirements from '../../src/providers/requirements_parser.js';

// A fresh process keeps earlier tests from warming up the shared Wasm runtime.
// Hold initialization open so every provider starts before any call completes.
const originalInit = Parser.init;
let initializationCalls = 0;
let release;
const gate = new Promise(resolve => { release = resolve; });
const initializationError = new Error('runtime initialization failed');
const retry = process.argv[2] === 'retry';
Parser.init = async function (...args) {
	const call = ++initializationCalls;
	await gate;
	if (retry && call === 1) {
		throw initializationError;
	}
	return originalInit.apply(this, args);
};

function startConsumers() {
	return Promise.allSettled([
		requirements.getParser(), requirements.getRequirementQuery(),
		gomod.getParser(), gomod.getRequireQuery(),
		containerfile.getParser(), containerfile.getFromQuery()
	]);
}

const pending = startConsumers();
const coldStartCalls = initializationCalls;
release();
let results = await pending;
const errorsPropagated = results.every(result => result.status === 'rejected' && result.reason === initializationError);
if (retry) {
	results = await startConsumers();
}

const inputs = ['blinker==1.9.0\n', 'module example.com/app\nrequire example.com/lib v1.2.3\n', 'FROM alpine:3.19\n'];
const captures = [];
for (let i = 0; i < results.length; i += 2) {
	const parserResult = results[i];
	const queryResult = results[i + 1];
	if (parserResult.status === 'rejected' || queryResult.status === 'rejected') {
		captures.push({ error: String(parserResult.reason ?? queryResult.reason) });
		continue;
	}
	const parser = parserResult.value;
	const query = queryResult.value;
	let tree;
	try {
		tree = parser.parse(inputs[i / 2]);
		captures.push(query.matches(tree.rootNode).flatMap(match =>
			match.captures.filter(capture => ['name', 'image'].includes(capture.name)).map(capture => capture.node.text)
		));
	} catch (error) {
		captures.push({ error: String(error) });
	} finally {
		tree?.delete();
		query.delete();
		parser.delete();
	}
}
console.log(JSON.stringify({ coldStartCalls, initializationCalls, errorsPropagated, captures }));
