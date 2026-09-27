"""One name for each package and each advisory, whichever engine reports them, and the fingerprint built from both.

Trivy names an advisory by its CVE; OSV-Scanner by its GHSA or PYSEC, with the CVE as an alias. Each engine also writes
the ecosystem its own way (`pip`, `poetry`, `PyPI`…). Normalizing all of that recognizes the same advisory on the same
package and version, so every engine (and the image scan) gives a finding the same fingerprint.
"""

from __future__ import annotations

import hashlib
import re

# Each engine's package type → a common family.
FAMILY = {
    # JavaScript
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
    # Python
    "pypi": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi", "pdm": "pypi",
    "python": "pypi", "python-pkg": "pypi", "conda-pkg": "pypi",
    # .NET
    "nuget": "nuget", "dotnet-core": "nuget", "dotnet": "nuget", "packages-props": "nuget",
    # Go, Rust, PHP, Ruby
    "go": "go", "gomod": "go", "gobinary": "go", "go-module": "go",
    "crates.io": "cargo", "cargo": "cargo", "rust-binary": "cargo", "rust-crate": "cargo",
    "packagist": "composer", "composer": "composer", "php-composer": "composer",
    "rubygems": "rubygems", "bundler": "rubygems", "gemspec": "rubygems", "gem": "rubygems",
    # JVM
    "maven": "maven", "pom": "maven", "gradle": "maven", "sbt": "maven", "jar": "maven", "java-archive": "maven",
    # Others
    "pub": "pub", "hex": "hex", "mix": "hex", "swifturl": "swift", "swift": "swift", "cocoapods": "cocoapods",
    "conancenter": "conan", "conan": "conan",
}
# Operating system packages (in container images), by distribution (Trivy) or package format (Grype): one family.
OS_FAMILIES = {"deb", "apk", "rpm", "debian", "ubuntu", "alpine", "redhat", "centos", "rocky", "alma", "amazon", "oracle", "photon", "suse",
               "opensuse", "opensuse.leap", "sles", "wolfi", "chainguard", "mariner", "azurelinux", "fedora", "bitnami"}


def family(ecosystem: str) -> str:
    value = (ecosystem or "").lower()
    return "os" if value in OS_FAMILIES else FAMILY.get(value, value or "unknown")


def package_name(ecosystem: str, name: str) -> str:
    """PyPI treats `-`, `_` and `.` alike (PEP 503); elsewhere, in practice, only case."""
    value = (name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", value) if family(ecosystem) == "pypi" else value


def canonical_id(identifiers: set[str], fallback: str) -> str:
    """The CVE if there is one (the name shared across databases); otherwise the engine's own identifier."""
    cves = sorted(item for item in identifiers if item.startswith("CVE-"))
    return cves[0] if cves else fallback


def fingerprint(scanner: str, rule: str, ecosystem: str, name: str, version: str) -> str:
    """Stable across runs and independent of the path: the key that keeps tickets from repeating."""
    return hashlib.sha256(f"{scanner}|{rule}|{ecosystem}|{name}|{version}".encode()).hexdigest()


def dependency_fingerprint(identifiers: set[str], fallback: str, ecosystem: str, name: str, version: str) -> str:
    """The fingerprint of an advisory on a package version, the same whichever engine names it and however."""
    return fingerprint("sca", canonical_id(set(identifiers) | {fallback}, fallback), family(ecosystem),
                       package_name(ecosystem, name), str(version or ""))
