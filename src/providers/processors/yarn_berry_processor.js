import { EOL } from 'os';

import { toPurl, toPurlFromString } from "../../tools.js";
import { purlType } from "../base_javascript.js";

import Yarn_processor from "./yarn_processor.js";

/**
 * Processor for Yarn Berry package manager
 * Handles parsing and processing of dependencies for Yarn Berry projects
 */
export default class Yarn_berry_processor extends Yarn_processor {

	static LOCATOR_PATTERN = /^(@?[^@]+(?:\/[^@]+)?)@npm:(.+)$/;
	static VIRTUAL_LOCATOR_PATTERN = /^(@?[^@]+(?:\/[^@]+)?)@virtual:[^#]+#npm:(.+)$/;

	/**
	 * Returns the command arguments for listing dependencies
	 * @param {boolean} includeTransitive - Whether to include transitive dependencies
	 * @returns {string[]} Command arguments for listing dependencies
	 */
	listCmdArgs(includeTransitive) {
		return ['info', includeTransitive ? '--recursive' : '--all', '--json'];
	}

	/**
	 * Returns the command arguments for updating the lock file
	 * @param {string}  - Directory containing the manifest file
	 * @returns {string[]} Command arguments for updating the lock file
	 */
	updateLockFileCmdArgs() {
		return ['install', '--immutable'];
	}

	/**
   * Parses the dependency tree output from Yarn Berry
   * Converts multiple JSON objects into a valid JSON array
   * @param {string} output - The raw command output
   * @returns {string} Properly formatted JSON string
   */
	parseDepTreeOutput(output) {
		// Normalize line endings to EOL regardless of platform
		const normalizedOutput = output.replace(/\r\n|\n/g, EOL);
		const lines = normalizedOutput.split(EOL).filter(line => line.trim());
		// Transform multiline JSON objects into a valid JSON array
		const outputArray = lines.join('').replaceAll('}{', '},{');
		return `[${outputArray}]`;
	}

	/**
   * Extracts root dependencies from the dependency tree
   * @param {Object} depTree - The dependency tree object
   * @returns {Map<string, PackageURL>} Map of dependency names to their PackageURL objects
   */
	getRootDependencies(depTree) {
		if (!depTree) {
			return new Map();
		}

		return new Map(
			depTree.filter(dep => !this.#isRoot(dep.value))
				.map(dep => {
					const depName = dep.value;
					const idx = depName.lastIndexOf('@');
					const name = depName.substring(0, idx);
					const version = dep.children.Version;
					return [name, toPurl(purlType, name, version)];
				})
				.filter(([name]) => this._manifest.dependencies.includes(name))
		);
	}

	/**
   * Checks if a dependency is the root package
   * @param {string} name - Name of the dependency
   * @returns {boolean} True if the dependency is the root package
   * @private
   */
	#isRoot(name) {
		if (!name) {
			return false;
		}
		return name.endsWith("@workspace:.");
	}

	/**
   * Adds dependencies to the SBOM
   * @param {Sbom} sbom - The SBOM object to add dependencies to
   * @param {Object} depTree - The dependency tree object
   */
	addDependenciesToSbom(sbom, depTree) {
		if (!depTree) {
			return;
		}

		// Build index of nodes by their value for quick lookup
		const nodeIndex = new Map();
		depTree.forEach(n => nodeIndex.set(n.value, n));

		// Determine the set of node values reachable from root via production deps
		const prodDeps = new Set(this._manifest.dependencies);
		const reachable = new Set();
		const queue = [];

		// Seed with root's production dependencies
		const rootNode = depTree.find(n => this.#isRoot(n.value));
		if (rootNode?.children?.Dependencies) {
			for (const d of rootNode.children.Dependencies) {
				const to = this.#purlFromLocator(d.locator);
				if (to) {
					const fullName = to.namespace ? `${to.namespace}/${to.name}` : to.name;
					if (prodDeps.has(fullName)) {
						queue.push(d.locator);
					}
				}
			}
		}

		// BFS to find all transitively reachable packages
		while (queue.length > 0) {
			const locator = queue.shift();
			if (reachable.has(locator)) {continue;}
			reachable.add(locator);

			const node = nodeIndex.get(this.#nodeValueFromLocator(locator));
			if (node?.children?.Dependencies) {
				for (const d of node.children.Dependencies) {
					if (!reachable.has(d.locator)) {
						queue.push(d.locator);
					}
				}
			}
		}

		// Only emit edges for root and reachable nodes
		depTree.forEach(n => {
			const depName = n.value;
			const isRoot = this.#isRoot(depName);
			if (!isRoot && !this.#isReachableNode(depName, reachable)) {return;}

			const from = isRoot ? toPurlFromString(sbom.getRoot().purl) : this.#purlFromNode(depName, n);
			const deps = n.children?.Dependencies;
			if(!deps) {return;}
			deps.forEach(d => {
				if (!reachable.has(d.locator)) {return;}
				const to = this.#purlFromLocator(d.locator);
				if(to) {
					sbom.addDependency(from, to);
				}
			});
		})
	}

	/**
	 * Converts a locator to the node value format used in yarn info output
	 * @param {string} locator - e.g. "express@npm:4.17.1"
	 * @returns {string} The node value, same as locator for non-virtual
	 * @private
	 */
	#nodeValueFromLocator(locator) {
		// Virtual locators: "@scope/name@virtual:hash#npm:version" → "@scope/name@npm:version"
		const virtualMatch = Yarn_berry_processor.VIRTUAL_LOCATOR_PATTERN.exec(locator);
		if (virtualMatch) {
			return `${virtualMatch[1]}@npm:${virtualMatch[2]}`;
		}
		return locator;
	}

	/**
	 * Checks if a node is in the reachable set by matching its value against reachable locators
	 * @param {string} depName - The node value (e.g. "express@npm:4.17.1")
	 * @param {Set<string>} reachable - Set of reachable locators
	 * @returns {boolean}
	 * @private
	 */
	#isReachableNode(depName, reachable) {
		if (reachable.has(depName)) {return true;}
		// Check if any reachable locator resolves to this node value
		for (const locator of reachable) {
			if (this.#nodeValueFromLocator(locator) === depName) {return true;}
		}
		return false;
	}

	/**
   * Creates a PackageURL from a dependency locator
   * @param {string} locator - The dependency locator
   * @returns {PackageURL|undefined} The PackageURL or undefined if not valid
   * @private
   */
	#purlFromLocator(locator) {
		if (!locator) {
			return undefined;
		}

		const matches = Yarn_berry_processor.LOCATOR_PATTERN.exec(locator);
		if (matches) {
			return toPurl(purlType, matches[1], matches[2]);
		}

		const virtualMatches = Yarn_berry_processor.VIRTUAL_LOCATOR_PATTERN.exec(locator);
		if (virtualMatches) {
			return toPurl(purlType, virtualMatches[1], virtualMatches[2]);
		}

		return undefined;
	}

	/**
   * Creates a PackageURL from a dependency node
   * @param {string} depName - The dependency name
   * @param {Object} node - The dependency node object
   * @returns {PackageURL|undefined} The PackageURL or undefined if not valid
   * @private
   */
	#purlFromNode(depName, node) {
		if (!node?.children?.Version) {
			return undefined;
		}

		const name = depName.substring(0, depName.lastIndexOf('@'));
		const version = node.children.Version;
		return toPurl(purlType, name, version);
	}
}
