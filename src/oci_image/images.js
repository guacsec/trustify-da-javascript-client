import { PackageURL } from "packageurl-js";

import { Platform } from "./platform.js";
import { getImageDigests, getImagePlatform } from "./utils.js";

/**
* Helper class for parsing docker repository/image names:
*
* - If the first part before the slash contains a "." or a ":" it is considered to be a registry URL
* - A last part starting with a ":" is considered to be a tag
* - The rest is considered the repository name (which might be separated via slashes)
*
* Example of valid names:
*
* - consol/tomcat-8.0
* - consol/tomcat-8.0:8.0.9
* - docker.consol.de:5000/tomcat-8.0
* - docker.consol.de:5000/jolokia/tomcat-8.0:8.0.9
*/
export class Image {
	static NAME_COMPONENT_REGEXP = '[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?';
	static DOMAIN_COMPONENT_REGEXP = '(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])';
	static NAME_COMP_REGEXP = new RegExp(this.NAME_COMPONENT_REGEXP);
	static IMAGE_NAME_REGEXP = new RegExp(this.NAME_COMPONENT_REGEXP + '(?:(?:/' + this.NAME_COMPONENT_REGEXP + ')+)?');
	static DOMAIN_REGEXP = new RegExp('^' + this.DOMAIN_COMPONENT_REGEXP + '(?:\\.' + this.DOMAIN_COMPONENT_REGEXP + ')*(?::[0-9]+)?$');
	static TAG_REGEXP = new RegExp('^[\\w][\\w.-]{0,127}$');
	static DIGEST_REGEXP = new RegExp('^sha256:[a-z0-9]{32,}$');

	/**
	 *
	 * @param {string} fullName
	 * @param {string} [givenTag]
	 */
	constructor(fullName, givenTag) {
		this.repository = '';
		this.registry = '';
		this.tag = '';
		this.digest = '';
		this.user = '';

		if (fullName == null) {
			throw new Error('Image name must not be null');
		}

		// Set digest to null as default
		this.digest = null;

		// Check if digest is part of fullName
		if (fullName.includes('@sha256')) {
			const digestParts = fullName.split('@');
			this.digest = digestParts[1];
			fullName = digestParts[0];
		}

		// Check for tag
		const tagPattern = /^(.+?)(?::([^:/]+))?$/;
		const matcher = fullName.match(tagPattern);
		if (!matcher) {
			throw new Error(fullName + ' is not a proper image name ([registry/][repo][:port]');
		}

		this.tag = givenTag != null ? givenTag : matcher[2];
		const rest = matcher[1];

		this.parseComponentsBeforeTag(rest);

		if (this.tag == null && this.digest == null) {
			this.tag = 'latest';
		}

		this.doValidate();
	}

	/**
	* @param {string[]} parts
	* @returns {string}
	*/
	joinTail(parts) {
		let builder = '';
		for (let i = 1; i < parts.length; i++) {
			builder += parts[i];
			if (i < parts.length - 1) {
				builder += '/';
			}
		}
		return builder;
	}

	/**
	* @param {string} part
	* @returns {boolean}
	*/
	isRegistry(part) {
		return part.includes('.') || part.includes(':');
	}

	/**
	* @param {string} [optionalRegistry]
	* @returns {string}
	*/
	getNameWithoutTag(optionalRegistry) {
		let ret = '';
		if (this.registry != null || optionalRegistry != null) {
			ret += (this.registry != null ? this.registry : optionalRegistry) + '/';
		}
		ret += this.repository;
		return ret;
	}

	/**
	* @param {string} [optionalRegistry]
	* @returns {string}
	*/
	getFullName(optionalRegistry) {
		let fullName = this.getNameWithoutTag(optionalRegistry);
		if (this.tag != null) {
			fullName = fullName + ':' + this.tag;
		}
		if (this.digest != null) {
			fullName = fullName + '@' + this.digest;
		}
		return fullName;
	}

	/**
	* @returns {string}
	*/
	getSimpleName() {
		const prefix = this.user + '/';
		return this.repository.startsWith(prefix) ? this.repository.substring(prefix.length) : this.repository;
	}

	/**
	* @param {string} optionalRepository
	* @returns {string}
	*/
	getNameWithOptionalRepository(optionalRepository) {
		if (optionalRepository != null) {
			const simpleName = this.getFullName();
			const simpleNameParts = simpleName.split('/');
			if (simpleNameParts.length > 0) {
				return optionalRepository + '/' + simpleNameParts[simpleNameParts.length - 1];
			}
		}
		return this.getFullName();
	}

	doValidate() {
		const errors = [];
		const image = this.user != null ? this.repository.substring(this.user.length + 1) : this.repository;

		/** @type {[[string, RegExp, string]]} */
		const checks = [
			['registry', Image.DOMAIN_REGEXP, this.registry],
			['image', Image.IMAGE_NAME_REGEXP, image],
			['user', Image.NAME_COMP_REGEXP, this.user],
			['tag', Image.TAG_REGEXP, this.tag],
			['digest', Image.DIGEST_REGEXP, this.digest]
		];

		for (const [name, pattern, value] of checks) {
			if (value != null && !pattern.test(value)) {
				errors.push(`${name} part '${value}' doesn't match allowed pattern '${pattern.source}'`);
			}
		}

		if (errors.length > 0) {
			const message = `Given Docker name '${this.getFullName()}' is invalid:\n` +
				errors.map(error => `   * ${error}`).join('\n') +
				'\nSee http://bit.ly/docker_image_fmt for more details';
			throw new Error(message);
		}
	}

	/**
	* @param {string} rest
	*/
	parseComponentsBeforeTag(rest) {
		const parts = rest.split(/\s*\/\s*/);
		if (parts.length === 1) {
			this.registry = null;
			this.user = null;
			this.repository = parts[0];
		} else if (parts.length >= 2) {
			if (this.isRegistry(parts[0])) {
				this.registry = parts[0];
				if (parts.length > 2) {
					this.user = parts[1];
					this.repository = this.joinTail(parts);
				} else {
					this.user = null;
					this.repository = parts[1];
				}
			} else {
				this.registry = null;
				this.user = parts[0];
				this.repository = rest;
			}
		}
	}
}

export class ImageRef {
	static OCI_TYPE = "oci";
	static REPOSITORY_QUALIFIER = "repository_url";
	static TAG_QUALIFIER = "tag";
	static ARCH_QUALIFIER = "arch";
	static OS_QUALIFIER = "os";
	static VARIANT_QUALIFIER = "variant";

	/** @type {Image} */
	image;
	/** @type {Platform} */
	platform;

	/**
	 * @param {string} image
	 * @param {string} [platform]
	 * @param {import("index.js").Options} [opts={}]
	 */
	constructor(image, platform, opts) {
		this.image = new Image(image);

		if (platform != null) {
			this.platform = Platform.fromString(platform);
		}

		this.checkImageDigest(opts);
	}

	/**
	 * @private
	 */
	checkImageDigest(opts) {
		if (this.image.digest == null) {
			try {
				const digests = getImageDigests(this, opts);
				if (digests.size === 0) {
					throw new Error("Failed to get any image digest");
				}
				if (digests.size === 1 && digests[Platform.EMPTY.toString()]) {
					this.image.digest = digests[Platform.EMPTY.toString()];
				} else {
					if (this.platform == null) {
						this.platform = getImagePlatform(opts);
					}
					if (this.platform == null) {
						throw new Error(`Failed to get image platform for image digest`);
					}
					if (!digests[this.platform.toString()]) {
						throw new Error(`Failed to get image digest for platform ${this.platform}`);
					}
					this.image.digest = digests[this.platform.toString()];
				}
			} catch (ex) {
				throw new Error("Failed to get image digest", { cause: ex });
			}
		}
	}

	/**
	 * @returns {PackageURL}
	 * @throws {Error}
	 * @see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#oci
	 */
	getPackageURL() {
		/** @type {Object.<string, string>} */
		const qualifiers = {};
		let repositoryUrl = this.image.getNameWithoutTag();
		const simpleName = this.image.getSimpleName();

		// Normalize Docker Hub image references so all forms produce the same PURL:
		//   node         → docker.io/node
		//   docker.io/library/node → docker.io/node
		if (repositoryUrl != null) {
			const lower = repositoryUrl.toLowerCase();
			if (lower === simpleName.toLowerCase()) {
				// Bare name (e.g. "node") — default to docker.io
				repositoryUrl = `docker.io/${simpleName}`;
			} else if (lower.startsWith('docker.io/library/')) {
				// Official image with library/ prefix — strip it
				repositoryUrl = `docker.io/${lower.substring('docker.io/library/'.length)}`;
			}
		}

		if (repositoryUrl != null && repositoryUrl.toLowerCase() !== simpleName.toLowerCase()) {
			qualifiers[ImageRef.REPOSITORY_QUALIFIER] = repositoryUrl.toLowerCase();
		}

		if (this.platform != null) {
			qualifiers[ImageRef.ARCH_QUALIFIER] = this.platform.architecture.toLowerCase();
			qualifiers[ImageRef.OS_QUALIFIER] = this.platform.os.toLowerCase();
			if (this.platform.variant != null) {
				qualifiers[ImageRef.VARIANT_QUALIFIER] = this.platform.variant.toLowerCase();
			}
		}

		const tag = this.image.tag;
		if (tag != null) {
			qualifiers[ImageRef.TAG_QUALIFIER] = tag;
		}

		return new PackageURL(
			ImageRef.OCI_TYPE,
			null,
			this.image.getSimpleName().toLowerCase(),
			this.image.digest.toLowerCase(),
			qualifiers,
			null
		);
	}
}
