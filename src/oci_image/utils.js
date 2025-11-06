import { delimiter, sep } from 'path';

import { getCustom, getCustomPath, invokeCommand } from '../tools.js';

import { ImageRef } from './images.js';
import { Platform } from './platform.js';

// Constants
const TRUSTIFY_DA_SYFT_CONFIG_PATH = "TRUSTIFY_DA_SYFT_CONFIG_PATH";
const TRUSTIFY_DA_SYFT_IMAGE_SOURCE = "TRUSTIFY_DA_SYFT_IMAGE_SOURCE";
const TRUSTIFY_DA_IMAGE_PLATFORM = "TRUSTIFY_DA_IMAGE_PLATFORM";
const TRUSTIFY_DA_IMAGE_OS = "TRUSTIFY_DA_IMAGE_OS";
const TRUSTIFY_DA_IMAGE_ARCH = "TRUSTIFY_DA_IMAGE_ARCH";
const TRUSTIFY_DA_IMAGE_VARIANT = "TRUSTIFY_DA_IMAGE_VARIANT";
const TRUSTIFY_DA_SKOPEO_CONFIG_PATH = "TRUSTIFY_DA_SKOPEO_CONFIG_PATH";
const TRUSTIFY_DA_IMAGE_SERVICE_ENDPOINT = "TRUSTIFY_DA_IMAGE_SERVICE_ENDPOINT";
const MEDIA_TYPE_DOCKER2_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";
const MEDIA_TYPE_DOCKER2_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json";
const MEDIA_TYPE_OCI1_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
const MEDIA_TYPE_OCI1_MANIFEST_LIST = "application/vnd.oci.image.index.v1+json";

const archMapping = {
	"amd64": "amd64",
	"x86_64": "amd64",
	"armv5tl": "arm",
	"armv5tel": "arm",
	"armv5tejl": "arm",
	"armv6l": "arm",
	"armv7l": "arm",
	"armv7ml": "arm",
	"arm64": "arm64",
	"aarch64": "arm64",
	"i386": "386",
	"i486": "386",
	"i586": "386",
	"i686": "386",
	"mips64le": "mips64le",
	"ppc64le": "ppc64le",
	"riscv64": "riscv64",
	"s390x": "s390x"
};

const variantMapping = {
	"armv5tl": "v5",
	"armv5tel": "v5",
	"armv5tejl": "v5",
	"armv6l": "v6",
	"armv7l": "v7",
	"armv7ml": "v7",
	"arm64": "v8",
	"aarch64": "v8"
};

/**
 *
 * @param {import('./images').ImageRef} imageRef
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {{}}
 */
export function generateImageSBOM(imageRef, opts = {}) {
	const output = execSyft(imageRef, opts);

	const node = JSON.parse(output);
	if (node['metadata'] != null) {
		const metadata = node['metadata'];
		if (metadata['component'] != null && typeof metadata['component'] === 'object') {
			const imagePurl = imageRef.getPackageURL().toString()
			metadata['component']['purl'] = imagePurl
			return node
		}
	}
}

/**
 *
 * @param {string} image
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {ImageRef}
 */
export function parseImageRef(image, opts) {
	const parts = image.split('^^')
	if (parts[0].trim() === image) {
		return new ImageRef(image, null, opts);
	} else if (parts.length === 2) {
		return new ImageRef(parts[0], parts[1], opts);
	} else {
		throw new Error(`Failed to parse OCI image ref "${image}", should be in the format "image^^architecture" or "image"`)
	}
}

/**
 * Executes Syft to generate SBOM
 * @param {import('./images').ImageRef} imageRef - The image reference
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 */
function execSyft(imageRef, opts = {}) {
	const syft = getCustomPath("syft", opts);
	const docker = getCustomPath("docker", opts);
	const podman = getCustomPath("podman", opts);

	const syftConfigPath = getCustom(TRUSTIFY_DA_SYFT_CONFIG_PATH, "", opts);
	const imageSource = getCustom(TRUSTIFY_DA_SYFT_IMAGE_SOURCE, "", opts);
	// Confirm image source exists, this will throw an error if not
	getImageSource(imageSource);

	const dockerPath =
		docker?.includes(sep)
			? docker.substring(0, docker.lastIndexOf(sep) + 1)
			: "";
	const podmanPath =
		podman?.includes(sep)
			? podman.substring(0, podman.lastIndexOf(sep) + 1)
			: "";
	const envs = getSyftEnvs(dockerPath, podmanPath);

	const scheme = imageRef.image.getFullName()

	const args = [
		scheme,
		"-s",
		"all-layers",
		"-o",
		"cyclonedx-json@1.5",
		"-q",
		...(syftConfigPath ? ["-c", syftConfigPath] : []),
		...(imageSource ? ["--from", imageSource] : []),
	];

	try {
		return invokeCommand(syft, args, {
			env: { ...process.env, ...envs },
			// 10MB, this output can be large so we need more than default
			maxBuffer: 1024 * 1024 * 10
		})
	} catch (error) {
		if (error.code === 'ENOENT') {
			throw new Error(`syft binary not accessible at ${syft}`)
		}
		throw new Error(`failed to invoke syft to generate OCI image SBOM`, {cause: error})
	}
}

/**
 * Gets the environment variables for Syft
 * @param {string} dockerPath - The Docker path
 * @param {string} podmanPath - The Podman path
 * @returns {Array<string>} - The environment variables
 */
function getSyftEnvs(dockerPath, podmanPath) {
	let path = null;
	if (dockerPath && podmanPath) {
		path = `${dockerPath}${File.pathSeparator}${podmanPath}`;
	} else if (dockerPath) {
		path = dockerPath;
	} else if (podmanPath) {
		path = podmanPath;
	}

	const prependPath = () => {
		const systemPath = process.env["PATH"];
		if (systemPath) {
			return `${systemPath}${delimiter}${path}`;
		} else {
			return `${path}`;
		}
	}
	return path ? { 'PATH': prependPath() } : {};
}

/**
 * Gets the platform information for an image
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {Platform|null} - The platform information or null
 */
export function getImagePlatform(opts = {}) {
	const platform = getCustom(TRUSTIFY_DA_IMAGE_PLATFORM, null, opts);
	if (platform) {
		return Platform.fromString(platform)
	}

	const imageSource = getCustom(TRUSTIFY_DA_SYFT_IMAGE_SOURCE, "", opts);
	const source = getImageSource(imageSource);

	let os = getCustom(TRUSTIFY_DA_IMAGE_OS, null, opts);
	if (!os) {
		os = source.getOs(opts);
	}
	let arch = getCustom(TRUSTIFY_DA_IMAGE_ARCH, null, opts);
	if (!arch) {
		arch = source.getArch(opts);
	}
	if (os && arch) {
		if (!Platform.isVariantRequired(os, arch)) {
			return Platform.fromComponents(os, arch, null);
		}

		let variant = getCustom(TRUSTIFY_DA_IMAGE_VARIANT, null, opts);
		if (!variant) {
			variant = source.getVariant(opts);
		}
		if (variant) {
			return Platform.fromComponents(os, arch, variant);
		}
	}

	return null;
}

/**
 * Gets information about a host from a container engine
 * @param {string} engine - The container engine name
 * @param {string} info - The information to retrieve
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The host information
 */
function hostInfo(engine, info, opts = {}) {
	const exec = getCustomPath(engine, opts);

	let output;
	try {
		output = invokeCommand(exec, ["info"]);
	} catch (error) {
		if (error.code === 'ENOENT') {
			throw new Error(`${engine} binary not accessible at ${exec}`)
		}
		throw new Error(`failed to invoke ${engine} to fetch host info`, {cause: error})
	}

	const lines = output.split("\n");
	for (const line of lines) {
		const trimmedLine = line.trimStart();
		if (trimmedLine.startsWith(`${info}:`)) {
			return line.trim().substring(info.length + 1).trim();
		}
	}
	return "";
}

/**
 * Gets the OS information from Docker
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The OS information
 */
function dockerGetOs(opts = {}) {
	return hostInfo("docker", "OSType", opts);
}

/**
 * Gets the architecture information from Docker
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The architecture information
 */
function dockerGetArch(opts = {}) {
	let arch = hostInfo("docker", "Architecture", opts);
	arch = archMapping[arch];
	return arch || "";
}

/**
 * Gets the variant information from Docker
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The variant information
 */
function dockerGetVariant(opts = {}) {
	let variant = hostInfo("docker", "Architecture", opts);
	variant = variantMapping[variant];
	return variant || "";
}

/**
 * Gets the OS information from Podman
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The OS information
 */
function podmanGetOs(opts = {}) {
	return hostInfo("podman", "os", opts);
}

/**
 * Gets the architecture information from Podman
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The architecture information
 */
function podmanGetArch(opts = {}) {
	return hostInfo("podman", "arch", opts);
}

/**
 * Gets the variant information from Podman
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The variant information
 */
function podmanGetVariant(opts = {}) {
	return hostInfo("podman", "variant", opts);
}

/**
 * Gets information from Docker or Podman
 * @param {function(Object): string} dockerSupplier - function to get information from Docker
 * @param {function(Object): string} podmanSupplier - function to get information from Podman
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {string} - The information
 */
function dockerPodmanInfo(dockerSupplier, podmanSupplier, opts = {}) {
	return dockerSupplier(opts) || podmanSupplier(opts);
}

/**
 * Gets the digests for an image
 * @param {import('./images').ImageRef} imageRef - The image reference
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {Object.<string, string>} - The image digests
 * @throws {Error} If the image info is invalid
 */
export function getImageDigests(imageRef, opts = {}) {
	const output = execSkopeoInspect(imageRef, true, opts);

	const node = JSON.parse(output);
	if (node.mediaType) {
		const mediaType = node.mediaType;
		if (typeof mediaType === "string") {
			switch (mediaType) {
			case MEDIA_TYPE_OCI1_MANIFEST:
			case MEDIA_TYPE_DOCKER2_MANIFEST:
				return getSingleImageDigest(imageRef, opts);

			case MEDIA_TYPE_OCI1_MANIFEST_LIST:
			case MEDIA_TYPE_DOCKER2_MANIFEST_LIST:
				return getMultiImageDigests(node);
			}
		}
	}

	throw new Error(`The image info is invalid: ${output}`);
}

/**
 * Gets digests for multiple images
 * @param {Object} node - The JSON node
 * @returns {Object.<string, string>} - The image digests
 */
function getMultiImageDigests(node) {
	if (node.manifests && Array.isArray(node.manifests)) {
		return node.manifests
			.filter(filterMediaType)
			.filter(filterDigest)
			.filter(filterPlatform)
			.reduce((result, manifestNode) => {
				const platformNode = manifestNode.platform;
				const arch = platformNode.architecture;
				const os = platformNode.os;
				let platform;

				if (platformNode.variant) {
					platform = Platform.fromComponents(os, arch, platformNode.variant);
				} else {
					platform = Platform.fromComponents(os, arch);
				}

				result[platform.toString()] = manifestNode.digest;
				return result;
			}, {});
	}
	return {};
}

/**
 * Filters manifest nodes by media type
 * @param {Object} manifestNode - The manifest node
 * @returns {boolean} - Whether the node passes the filter
 */
function filterMediaType(manifestNode) {
	if (manifestNode.mediaType) {
		const mediaType = manifestNode.mediaType;
		if (typeof mediaType === 'string') {
			return mediaType === MEDIA_TYPE_OCI1_MANIFEST ||
				mediaType === MEDIA_TYPE_DOCKER2_MANIFEST;
		}
	}
	return false;
}

/**
 * Filters manifest nodes by digest
 * @param {Object} manifestNode - The manifest node
 * @returns {boolean} - Whether the node passes the filter
 */
function filterDigest(manifestNode) {
	return manifestNode.digest && typeof manifestNode.digest === 'string';
}

/**
 * Filters manifest nodes by platform
 * @param {Object} manifestNode - The manifest node
 * @returns {boolean} - Whether the node passes the filter
 */
function filterPlatform(manifestNode) {
	if (manifestNode.platform && typeof manifestNode.platform === 'object') {
		const platformNode = manifestNode.platform;
		if (platformNode.architecture && platformNode.os &&
			typeof platformNode.architecture === 'string' &&
			typeof platformNode.os === 'string') {
			try {
				if (platformNode.variant && typeof platformNode.variant === 'string') {
					Platform.fromComponents(platformNode.os, platformNode.architecture, platformNode.variant);
					return true;
				}
				Platform.fromComponents(platformNode.os, platformNode.architecture);
				return true;
			} catch (e) {
				return false;
			}
		}
	}
	return false;
}

/**
 * Gets digest for a single image
 * @param {import('./images').ImageRef} imageRef - The image reference
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {Object.<string, string>} - The image digest
 */
function getSingleImageDigest(imageRef, opts = {}) {
	const output = execSkopeoInspect(imageRef, false, opts);

	const node = JSON.parse(output);

	if (node.Digest && typeof node.Digest === 'string') {
		const result = {};
		result[Platform.EMPTY.toString()] = node.Digest;
		return result;
	}
	return {};
}

/**
 * Executes Skopeo inspect
 * @param {import('./images').ImageRef} imageRef - The image reference
 * @param {boolean} raw - Whether to use raw output
 * @param {import("../index.js").Options} [opts={}] - optional various options to pass along the application
 */
function execSkopeoInspect(imageRef, raw, opts = {}) {
	const skopeo = getCustomPath("skopeo", opts);

	const configPath = getCustom(TRUSTIFY_DA_SKOPEO_CONFIG_PATH, null, opts);
	const daemonHost = getCustom(TRUSTIFY_DA_IMAGE_SERVICE_ENDPOINT, null, opts);

	const args = [
		"inspect",
		raw ? "--raw" : "",
		`docker://${imageRef.image.getFullName()}`,
		...(configPath ? ["--authfile", configPath] : []),
		...(daemonHost ? ["--daemon-host", daemonHost] : []),
	];

	try {
		return invokeCommand(skopeo, args);
	} catch (error) {
		if (error.code === 'ENOENT') {
			throw new Error(`skopeo binary not accessible at ${skopeo}`)
		}
		throw new Error(`failed to invoke skopeo to inspect OCI image(s)`, {cause: error})
	}
}

/**
 * @typedef SyftImageSource
 * @type {object}
 * @property {function(): string} getOs
 * @property {function(): string} getArch
 * @property {function(): string} getVariant
 */

/**
 * @typedef SyftImageSourceType
 * @type {object}
 * @property {function(Object): string} getOs
 * @property {function(Object): string} getArch
 * @property {function(Object): string} getVariant
 */

/** @type {function(string): SyftImageSourceType} */
const SyftImageSource = (name) => {
	switch (name) {
	case "":
	case "registry":
		return {
			getOs(opts = {}) {
				return dockerPodmanInfo(dockerGetOs, podmanGetOs, opts);
			},
			getArch(opts = {}) {
				return dockerPodmanInfo(dockerGetArch, podmanGetArch, opts);
			},
			getVariant(opts = {}) {
				return dockerPodmanInfo(dockerGetVariant, podmanGetVariant, opts);
			},
		};
	case "docker":
		return {
			getOs(opts = {}) {
				return dockerGetOs(opts);
			},
			getArch(opts = {}) {
				return dockerGetArch(opts);
			},
			getVariant(opts = {}) {
				return dockerGetVariant(opts);
			},
		};
	case "podman":
		return {
			getOs(opts = {}) {
				return podmanGetOs(opts);
			},
			getArch(opts = {}) {
				return podmanGetArch(opts);
			},
			getVariant(opts = {}) {
				return podmanGetVariant(opts);
			},
		};
	default:
		return null;
	}
};

/**
 * Gets an image source by name
 * @param {string} name - The image source name
 * @returns {Object} - The image source
 * @throws {Error} If the image source is not valid
 */
function getImageSource(name) {
	const source = SyftImageSource(name);
	if (!source) {
		throw new Error(`The image source for syft is not valid: ${name}`);
	}
	return source;
}
