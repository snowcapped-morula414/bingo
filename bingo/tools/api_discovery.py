"""
API Discovery Document Scanner
Automatically finds Swagger/OpenAPI/Google-style discovery docs on target sites.
evidence_level: VERIFIED (200 response confirmed) / LIKELY (partial) / INFERRED (pattern only)
Zero-Hallucination: never fabricates endpoints — all output is from real HTTP responses.
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

# ── Discovery document paths to probe ──────────────────────────────────────
_DISCOVERY_PATHS = [
    # OpenAPI / Swagger
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v1/openapi.json",
    "/api-docs",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/swagger.json",
    "/docs/openapi.json",
    # Google-style discovery
    "/$discovery/rest",
    "/discovery/v1/apis",
    # GraphQL
    "/graphql",
    "/graphiql",
    "/graphql/schema",
    "/api/graphql",
    # WSDL / SOAP
    "/api?wsdl",
    "/service?wsdl",
    # RAML
    "/api/raml",
    # Generic API roots
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/api/latest",
    "/wp-json",                 # WordPress
    "/.well-known/openapi.json",
    "/actuator/mappings",       # Spring Boot
]

# ── Headers that suggest an API doc response ────────────────────────────────
_API_DOC_CONTENT_TYPES = {
    "application/json",
    "application/x-yaml",
    "text/yaml",
    "application/yaml",
}

# ── JSON keys that confirm a Swagger/OpenAPI document ───────────────────────
_SWAGGER_KEYS = {"swagger", "openapi", "info", "paths", "definitions", "components"}

_TIMEOUT = 8


@dataclass
class DiscoveredEndpoint:
    path: str
    method: str
    description: str = ""
    parameters: list[str] = field(default_factory=list)
    evidence_level: str = "INFERRED"


@dataclass
class DiscoveryDoc:
    url: str
    doc_type: str          # "openapi", "swagger", "graphql", "google", "wordpress", "generic"
    version: str = ""
    title: str = ""
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    raw_paths: list[str] = field(default_factory=list)
    evidence_level: str = "VERIFIED"


@dataclass
class ApiDiscoveryResult:
    target: str
    docs_found: list[DiscoveryDoc] = field(default_factory=list)
    total_endpoints: int = 0
    interesting_paths: list[str] = field(default_factory=list)   # admin/user/auth paths
    error: str = ""


class ApiDiscoveryScanner:
    """Probes a target URL for API discovery documents and extracts endpoint lists."""

    def __init__(self, target: str, session: Optional[requests.Session] = None):
        self.target = target.rstrip("/")
        self.base = self._base_url(target)
        self.sess = session or requests.Session()
        self.sess.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept": "application/json,text/html,*/*",
        })
        self.sess.verify = False

    # ── Public API ──────────────────────────────────────────────────────────

    def scan(self) -> ApiDiscoveryResult:
        result = ApiDiscoveryResult(target=self.target)
        for path in _DISCOVERY_PATHS:
            url = urljoin(self.base, path)
            doc = self._probe(url)
            if doc:
                result.docs_found.append(doc)
                result.total_endpoints += len(doc.endpoints)
        result.interesting_paths = self._collect_interesting(result)
        return result

    # ── Internal ────────────────────────────────────────────────────────────

    @staticmethod
    def _base_url(target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _probe(self, url: str) -> Optional[DiscoveryDoc]:
        try:
            r = self.sess.get(url, timeout=_TIMEOUT, allow_redirects=False)
        except Exception:
            return None

        if r.status_code not in (200, 206):
            return None

        ct = r.headers.get("Content-Type", "").lower()

        # Try JSON parse
        try:
            data = r.json()
            return self._parse_json_doc(url, data)
        except Exception:
            pass

        # GraphQL introspection endpoint check
        if "graphql" in url.lower() and r.status_code == 200:
            return DiscoveryDoc(
                url=url,
                doc_type="graphql",
                title="GraphQL Endpoint",
                evidence_level="VERIFIED",
            )

        # WordPress REST API
        if "wp-json" in url and r.status_code == 200:
            return self._parse_wordpress(url, r.text)

        # Generic JSON API root
        if any(t in ct for t in _API_DOC_CONTENT_TYPES) or ct.startswith("application/json"):
            try:
                data = r.json()
                if isinstance(data, dict) and any(k in data for k in _SWAGGER_KEYS):
                    return self._parse_json_doc(url, data)
            except Exception:
                pass

        return None

    def _parse_json_doc(self, url: str, data: dict) -> Optional[DiscoveryDoc]:
        if not isinstance(data, dict):
            return None

        # Determine type and version
        if "openapi" in data:
            doc_type = "openapi"
            version = data.get("openapi", "")
        elif "swagger" in data:
            doc_type = "swagger"
            version = data.get("swagger", "")
        elif "kind" in data and data.get("kind") == "discovery#restDescription":
            doc_type = "google"
            version = data.get("version", "")
        else:
            doc_type = "generic"
            version = ""

        title = ""
        if "info" in data and isinstance(data["info"], dict):
            title = data["info"].get("title", "")

        endpoints: list[DiscoveredEndpoint] = []
        raw_paths: list[str] = []

        # OpenAPI / Swagger paths
        paths = data.get("paths", {})
        if isinstance(paths, dict):
            for path, methods in paths.items():
                raw_paths.append(path)
                if isinstance(methods, dict):
                    for method, detail in methods.items():
                        if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
                            continue
                        desc = ""
                        params: list[str] = []
                        if isinstance(detail, dict):
                            desc = detail.get("summary", detail.get("description", ""))
                            for p in detail.get("parameters", []):
                                if isinstance(p, dict):
                                    params.append(p.get("name", ""))
                        endpoints.append(DiscoveredEndpoint(
                            path=path,
                            method=method.upper(),
                            description=desc[:120],
                            parameters=params,
                            evidence_level="VERIFIED",
                        ))

        # Google Discovery Document resources
        resources = data.get("resources", {})
        if isinstance(resources, dict):
            for rname, rdata in resources.items():
                if isinstance(rdata, dict):
                    for mname, mdata in rdata.get("methods", {}).items():
                        if isinstance(mdata, dict):
                            path = mdata.get("flatPath", mdata.get("path", ""))
                            raw_paths.append(path)
                            endpoints.append(DiscoveredEndpoint(
                                path=path,
                                method=mdata.get("httpMethod", "GET"),
                                description=mdata.get("description", "")[:120],
                                evidence_level="VERIFIED",
                            ))

        return DiscoveryDoc(
            url=url,
            doc_type=doc_type,
            version=version,
            title=title,
            endpoints=endpoints,
            raw_paths=raw_paths,
            evidence_level="VERIFIED",
        )

    def _parse_wordpress(self, url: str, text: str) -> Optional[DiscoveryDoc]:
        endpoints: list[DiscoveredEndpoint] = []
        try:
            data = json.loads(text)
            routes = data.get("routes", {})
            for path, info in routes.items():
                methods = info.get("methods", ["GET"])
                endpoints.append(DiscoveredEndpoint(
                    path=path,
                    method=",".join(methods),
                    evidence_level="VERIFIED",
                ))
        except Exception:
            pass
        return DiscoveryDoc(
            url=url,
            doc_type="wordpress",
            title="WordPress REST API",
            endpoints=endpoints,
            evidence_level="VERIFIED",
        )

    @staticmethod
    def _collect_interesting(result: ApiDiscoveryResult) -> list[str]:
        _keywords = {"admin", "user", "auth", "login", "token", "secret",
                     "password", "config", "debug", "internal", "manage", "upload"}
        found: list[str] = []
        for doc in result.docs_found:
            for ep in doc.endpoints:
                low = ep.path.lower()
                if any(k in low for k in _keywords):
                    found.append(f"{ep.method} {ep.path}")
        return list(dict.fromkeys(found))  # deduplicate, preserve order
