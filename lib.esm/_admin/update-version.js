import https from "https";
import fs from "fs";
import { dirname, resolve as _resolve } from "path";
import { fileURLToPath } from 'url';
import { gunzipSync } from "zlib";
import { assert } from "../utils/errors.js";
import semver from "semver";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
export const ROOT = _resolve(__dirname, "../../");
export function getUrl(url) {
    const request = https.request(url, { method: "GET", headers: {} });
    request.end();
    return new Promise((resolve, reject) => {
        request.once("response", (resp) => {
            const statusCode = resp.statusCode || 0;
            const statusMessage = resp.statusMessage || "";
            const headers = Object.keys(resp.headers || {}).reduce((accum, name) => {
                let value = resp.headers[name] || "";
                if (Array.isArray(value)) {
                    value = value.join(", ");
                }
                accum[name] = value;
                return accum;
            }, {});
            let body = null;
            //resp.setEncoding("utf8");
            resp.on("data", (chunk) => {
                if (body == null) {
                    body = chunk;
                }
                else {
                    const newBody = new Uint8Array(body.length + chunk.length);
                    newBody.set(body, 0);
                    newBody.set(chunk, body.length);
                    body = newBody;
                }
            });
            resp.on("end", () => {
                if (headers["content-encoding"] === "gzip" && body) {
                    body = gunzipSync(body);
                }
                resolve({ statusCode, statusMessage, headers, body });
            });
            resp.on("error", (error) => {
                error.response = { statusCode, statusMessage, headers, body };
                reject(error);
            });
        });
        request.on("error", (error) => { reject(error); });
    });
}
export function loadJson(path) {
    return JSON.parse(fs.readFileSync(path).toString());
}
export function saveJson(filename, data, sort) {
    let replacer = undefined;
    if (sort) {
        replacer = (key, value) => {
            if (Array.isArray(value)) {
                // pass
            }
            else if (value && typeof (value) === "object") {
                const keys = Object.keys(value);
                let sortFunc;
                if (typeof (sort) === "function") {
                    sortFunc = function (a, b) {
                        return sort(key, a, b);
                    };
                }
                keys.sort(sortFunc);
                return keys.reduce((accum, key) => {
                    accum[key] = value[key];
                    return accum;
                }, {});
            }
            return value;
        };
    }
    atomicWrite(filename, JSON.stringify(data, replacer, 2) + "\n");
}
const Decoder = new TextDecoder();
const Cache = {};
export async function _getNpmPackage(name) {
    if (!Cache[name]) {
        const resp = await getUrl("https:/\/registry.npmjs.org/" + name);
        assert(resp.statusCode === 200 && resp.body != null, "bad registry response", resp);
        Cache[name] = JSON.parse(Decoder.decode(resp.body));
    }
    return Cache[name] || null;
}
export function resolve(...args) {
    args = args.slice();
    args.unshift(ROOT);
    return _resolve.apply(null, args);
}
export function atomicWrite(path, value) {
    const tmp = resolve(".atomic-tmp");
    fs.writeFileSync(tmp, value);
    fs.renameSync(tmp, path);
}
(async function () {
    const pkg = loadJson("package.json");
    const data = await _getNpmPackage(pkg.name);
    let versions = Object.keys(data.versions);
    const pkgVersion = pkg.version;
    // The package.json is already updated; done
    if (versions.indexOf(pkgVersion) === -1) {
        console.log(`Current version not published: ${pkgVersion}`);
        // Update the _version.ts
        atomicWrite(resolve("src.ts/_version.ts"), `export const version = ${JSON.stringify(pkgVersion)};\n`);
        return;
    }
    // Find all matching major.minor versions...
    const major = semver.major(pkgVersion), minor = semver.minor(pkgVersion);
    versions = versions.filter((v) => {
        return (semver.major(v) === major && semver.minor(v) === minor);
    });
    // Increment the version; beta builds get the prerelease tag incremented
    let version;
    if (semver.prerelease(pkgVersion)) {
        // Prereleases need to match the patch too, and have a prerelease
        const patch = semver.patch(pkgVersion);
        versions = versions.filter((v) => {
            return (semver.patch(v) === patch && semver.prerelease(v));
        });
        version = semver.inc(versions.pop(), "prerelease", "beta");
    }
    else {
        version = semver.inc(versions.pop(), "patch");
    }
    console.log(`Update version: ${pkgVersion} => ${version}`);
    // Update the _version.ts
    atomicWrite(resolve("src.ts/_version.ts"), `export const version = ${JSON.stringify(version)};\n`);
    // Update the JSON and write it to disk (sorted)
    pkg.version = version;
    saveJson("package.json", pkg, (key, a, b) => {
        // Keep exports/.xxx sorted with default last in the list.
        if (key[0] === ".") {
            if (a === "default") {
                return 1;
            }
            if (b === "default") {
                return -1;
            }
        }
        return a.localeCompare(b);
    });
})();
//# sourceMappingURL=update-version.js.map