import { toPurl, toPurlFromString } from "../../tools.js";
import { purlType } from "../base_javascript.js";

import Yarn_processor from "./yarn_processor.js";

/**
 * Processor for Yarn Classic package manager
 * Handles parsing and processing of dependencies for Yarn Classic projects
 */
export default class Yarn_classic_processor extends Yarn_processor {

	/**
	 * Returns the command arguments for listing dependencies
	 * @param {boolean} includeTransitive - Whether to include transitive dependencies
	 * @returns {string[]} Command arguments for listing dependencies
	 */
	listCmdArgs(includeTransitive) {
		return ['list', includeTransitive ? '--depth=Infinity' : '--depth=0', '--prod', '--frozen-lockfile', '--json'];
	}

	/**
	 * Returns the command arguments for updating the lock file
	 * @returns {string[]} Command arguments for updating the lock file
	 */
	updateLockFileCmdArgs() {
		return ['install', '--frozen-lockfile'];
	}

	/**
   * Parses the dependency tree output from Yarn Classic
   * @param {string} output - The raw command output
   * @returns {string} Unchanged output as it's already in JSON format
   */
	parseDepTreeOutput(output) {
		return output;
	}

	/**
   * Extracts root dependencies from the dependency tree
   * @param {Object} depTree - The dependency tree object
   * @returns {Map<string, PackageURL>} Map of dependency names to their PackageURL objects
   */
	getRootDependencies(depTree) {
		if (!depTree?.data?.trees) {
			return new Map();
		}

		return new Map(
			depTree.data.trees.map(
				dep => {
					const depName = dep.name;
					const idx = depName.lastIndexOf('@');
					const name = depName.substring(0, idx);
					const version = idx !== -1 ? depName.substring(idx + 1) : '';
					return [name, toPurl(purlType, name, version)];
				}
			)
		)
	}

	/**
   * Adds dependencies to the SBOM
   * @param {Sbom} sbom - The SBOM object to add dependencies to
   * @param {Object} depTree - The dependency tree object
   * @param {function(PackageURL): (Array<{alg: string, content: string}>|undefined)} [hashesForPurl] - Resolves lock-file hashes for a purl
   */
	addDependenciesToSbom(sbom, depTree, hashesForPurl = () => undefined) {
		if (!depTree?.data?.trees) {
			return;
		}

		const rootPurl = toPurlFromString(sbom.getRoot().purl);

		const purls = new Map();
		depTree.data.trees.forEach(n => {
			const dep = new NodeMetaData(n);
			if(this._manifest.dependencies.includes(dep.name)) {
				sbom.addDependency(rootPurl, dep.purl, undefined, hashesForPurl(dep.purl));
			}
			purls.set(dep.name, dep.purl);
		});

		depTree.data.trees.forEach(n => {
			this.#addChildrenToSbom(sbom, n, purls, hashesForPurl);
		});
	}

	/**
   * Recursively adds child dependencies to the SBOM
   * @param {Sbom} sbom - The SBOM object to add dependencies to
   * @param {Object} node - The current dependency node
   * @param {Map<string, PackageURL>} purls - Map of dependency names to their PackageURL objects
   * @param {function(PackageURL): (Array<{alg: string, content: string}>|undefined)} hashesForPurl - Resolves lock-file hashes for a purl
   * @private
   */
	#addChildrenToSbom(sbom, node, purls, hashesForPurl) {
		const dep = new NodeMetaData(node);
		const children = node.children ? node.children : [];
		children.forEach(c => {
			const child = new NodeMetaData(c);
			const from = dep.shadow ? purls.get(dep.name) : dep.purl;
			const to = child.shadow ? purls.get(child.name) : child.purl;
			if(from && to) {
				sbom.addDependency(from, to, undefined, hashesForPurl(to));
			}
			this.#addChildrenToSbom(sbom, c, purls, hashesForPurl);
		});
	}
}

/**
 * Helper class to extract and store metadata from a dependency node
 */
class NodeMetaData {
	/**
   * Creates a new NodeMetaData instance
   * @param {Object} node - The dependency node
   */
	constructor(node) {
		this.nodeName = node.name;
		const idx = this.nodeName.lastIndexOf('@');
		this.name = this.nodeName.substring(0, idx);
		this.version = idx !== -1 ? this.nodeName.substring(idx + 1) : '';
		this.purl = toPurl(purlType, this.name, this.version);
		const shadowNode = node.shadow;
		this.shadow = shadowNode ? shadowNode : false;
	}
}
