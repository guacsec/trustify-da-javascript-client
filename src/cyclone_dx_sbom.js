import {EOL} from "os";

import {PackageURL} from "packageurl-js";

/**
 *
 * @param component {PackageURL}
 * @param type type of package - application or library
 * @param scope scope of the component - runtime or compile
 * @return {{"bom-ref": string, name, purl: string, type, version, scope}}
 * @private
 */
function getComponent(component, type, scope) {
	let componentObject;
	if(component instanceof PackageURL)
	{
		if(component.namespace) {
			componentObject = {
				"group": component.namespace,
				"name": component.name,
				"version": component.version,
				"purl": component.toString(),
				"type": type,
				"bom-ref": component.toString(),
				"scope": scope
			}
		}
		else
		{
			componentObject = {
				"name": component.name,
				"version": component.version,
				"purl": component.toString(),
				"type": type,
				"bom-ref": component.toString(),
				"scope": scope
			}
		}
	}
	else
	{
		componentObject = component
	}
	return componentObject
}


function createDependency(dependency)
{
	return {
		"ref" : dependency,
		"dependsOn" : new Array()
	}

}



export default class CycloneDxSbom {

	sbomObject
	rootComponent
	components
	dependencies
	sourceManifestForAuditTrail

	constructor() {
		this.dependencies = new Array()
		this.components = new Array()


	}

	/**
	 * @param {PackageURL} root - add main/root component for sbom
	 * @return {CycloneDxSbom} the CycloneDxSbom Sbom Object
	 */
	addRoot(root) {

		this.rootComponent =
			getComponent(root, "application")
		this.components.push(this.rootComponent)
		return this
	}


	/**
	 * @return {{{"bom-ref": string, name, purl: string, type, version}}} root component of sbom.
	 */
	getRoot() {
		return this.rootComponent
	}

	/**
	 * Adds a dependency relationship between two components in the SBOM
	 * @param {PackageURL} sourceRef - The source component (parent)
	 * @param {PackageURL} targetRef - The target component (dependency)
	 * @return {CycloneDxSbom} The updated SBOM
	 */
	addDependency(sourceRef, targetRef, scope) {
		const sourcePurl = sourceRef.toString();
		const targetPurl = targetRef.toString();

		// Ensure both components exist in the components list
		[sourceRef, targetRef].forEach((ref, index) => {
			const purl = index === 0 ? sourcePurl : targetPurl;
			if (this.getComponentIndex(purl) < 0) {
				this.components.push(getComponent(ref, "library", scope));
			}
		});

		// Ensure source dependency exists
		let sourceDepIndex = this.getDependencyIndex(sourcePurl);
		if (sourceDepIndex < 0) {
			this.dependencies.push(createDependency(sourcePurl));
			sourceDepIndex = this.dependencies.length - 1;
		}

		// Add target to source's dependencies if not already present
		if (!this.dependencies[sourceDepIndex].dependsOn.includes(targetPurl)) {
			this.dependencies[sourceDepIndex].dependsOn.push(targetPurl);
		}

		// Ensure target dependency exists
		if (this.getDependencyIndex(targetPurl) < 0) {
			this.dependencies.push(createDependency(targetPurl));
		}

		return this;
	}

	/** @param {{}} opts - various options, settings and configuration of application.
 	 * @return String CycloneDx Sbom json object in a string format
	 */
	getAsJsonString(opts) {
		let manifestType = opts["manifest-type"]
		this.setSourceManifest(opts["source-manifest"])
		this.sbomObject = {
			"bomFormat": "CycloneDX",
			"specVersion": "1.4",
			"version": 1,
			"metadata": {
				"timestamp": new Date(),
				"component": this.rootComponent,
				"properties": new Array()
			},
			"components": this.components,
			"dependencies": this.dependencies
		}
		if (this.rootComponent === undefined)
		{
			delete this.sbomObject.metadata.component
		}
		if(this.sourceManifestForAuditTrail !== undefined  && manifestType !== undefined) {
			this.sbomObject.metadata.properties.push({"name" : "rhda:manifest:content" , "value" : this.sourceManifestForAuditTrail})
			this.sbomObject.metadata.properties.push({"name" : "rhda:manifest:filename" , "value" : manifestType})
		}
		else {
			delete this.sbomObject.metadata.properties
		}

		if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
			console.log("SBOM Generated for manifest, to be sent to exhort service:" + EOL + JSON.stringify(this.sbomObject, null, 4))
		}
		return JSON.stringify(this.sbomObject)
	}

	/**
	 *
	 * @param {String} dependency - purl string of the component.
	 * @return {int} - the index of the dependency in dependencies Array, returns -1 if not found.
	 */
	getDependencyIndex(dependency) {
		return this.dependencies.findIndex(dep => dep.ref === dependency)
	}

	/**
	 *
	 * @param {component} theComponent - Component Object with purl field.
	 * @return {int} index of the found component entry, if not found returns -1.
	 * @private
	 */
	getComponentIndex(theComponent) {
		return this.components.findIndex(component => component.purl === theComponent)
	}

	/** This method gets a PackageUrl, and returns a Component of CycloneDx Sbom
	 * @param purl {PackageURL}
	 * @return component
	 */
	purlToComponent(purl) {
		return getComponent(purl, "library")
	}

	/**
	 * This method gets an array of dependencies to be ignored, and remove all of them from CycloneDx Sbom
	 * @param {Array[PackageURL]} dependencies to be removed from sbom
	 * @return {CycloneDxSbom} without ignored dependencies
	 */
	filterIgnoredDeps(deps) {
		deps.forEach(dep => {
			let index = this.components.findIndex(component => component.name === dep.name && component.group === dep.namespace);
			if (index === -1) {
				return;
			}
			const depPurl = this.components[index].purl;
			this.components.splice(index, 1)
			index = this.dependencies.findIndex(dependency => dependency.ref.includes(dep));
			if (index === -1) {
				return;
			}
			this.dependencies.splice(index, 1)
			this.dependencies.forEach(dependency => {
				let indexDependsOn = dependency.dependsOn.findIndex(theDep => theDep.includes(depPurl));
				if (indexDependsOn > -1) {
					dependency.dependsOn.splice(indexDependsOn, 1)
				}
			})
		})
		return this
	}

	/**
	 * This method gets an array of dependencies with versions( purl string format) to be ignored, and remove all of them from CycloneDx Sbom
	 * @param {Array} dependencies to be removed from sbom
	 * @return {CycloneDxSbom} without ignored dependencies
	 */
	filterIgnoredDepsIncludingVersion(deps) {
		deps.forEach(dep => {
			let index = this.components.findIndex(component => component.purl === dep);
			if (index >= 0) {
				this.components.splice(index, 1)
			}
			index = this.dependencies.findIndex(dependency => dependency.ref === dep);
			if (index >= 0) {
				this.dependencies.splice(index, 1)
			}

			this.dependencies.forEach(dependency => {
				let indexDependsOn = dependency.dependsOn.findIndex(theDep => theDep === dep);
				if (indexDependsOn > -1) {
					dependency.dependsOn.splice(indexDependsOn, 1)
				}
			})
		})
		return this
	}

	/** This method gets a component object, and a string name, and checks if the name is a substring of the component' purl.
	 * @param {} component to search in its dependencies
	 * @param {String} name to be checked.
	 *
	 * @return {boolean}
	 */
	checkIfPackageInsideDependsOnList(component, name) {

		let dependencyIndex = this.getDependencyIndex(component.purl)
		if (dependencyIndex < 0) {
			return false
		}

		//Only if the dependency doesn't exists on the dependency list of dependency, then add it to this list.
		if (this.dependencies[dependencyIndex].dependsOn.findIndex(dep => dep.includes(name)) >= 0) {
			return true;
		} else {
			return false
		}
	}

	/** Removes the root component from the sbom
	 */
	removeRootComponent() {
		let compIndex = this.getComponentIndex(this.rootComponent)
		let depIndex = this.getDependencyIndex(this.rootComponent.purl)
		this.components.splice(compIndex, 1)
		this.dependencies.splice(depIndex, 1)
		this.rootComponent = undefined
	}

	setSourceManifest(manifestData) {
		this.sourceManifestForAuditTrail = manifestData
	}
}
