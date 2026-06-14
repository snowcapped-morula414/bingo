"""
Ruby Web App Fuzzing Surface Detection — Ruzzy + LibAFL Attack Surface Mapper
Skill #54 — RubyLibAFLFuzz

Research basis:
  Matt Schwager (Trail of Bits)
  "Extending Ruzzy with LibAFL"
  https://blog.trailofbits.com/2026/04/29/extending-ruzzy-with-libafl/
  Published: April 29, 2026 | Ruzzy 0.8.0 released with LibAFL support

Background:
  Ruzzy = coverage-guided fuzzer for pure Ruby code and Ruby C extensions
  (originally built on LLVM libFuzzer, now also supports LibAFL).
  LibAFL = Rust-based next-gen fuzzer with libFuzzer compatibility layer,
  improved performance, and actively maintained (libFuzzer in maintenance mode).

  Key technical insight:
  - LibAFL requires coverage maps to be registered BEFORE LLVMFuzzerRunDriver starts
    (unlike libFuzzer which lazily accepts them at runtime)
  - LibAFL's libFuzzer.a contains .preinit_array sections → must use lld not GNU ld
  - Ruby C extensions (.so files) must be require'd before fuzz() call, not inside lambda

bingo integration scope (web pentesting):
  This module focuses on ATTACK SURFACE DISCOVERY for Ruby-based web applications:

  1. Ruby framework detection (Rails, Sinatra, Hanami, Grape, Padrino, Roda)
  2. Ruby C extension parser endpoints (JSON, XML, CSV, YAML, MessagePack, Protobuf,
     image/audio processing via ImageMagick/RMagick, nokogiri, oj, msgpack)
  3. File upload endpoints that pipe data to Ruby C extensions
  4. Binary data / custom protocol deserialization endpoints
  5. GraphQL endpoints (graphql-ruby gem with C parser)
  6. YAML deserialization risk detection (Psych/SafeLoad bypass patterns)
  7. Gem version fingerprinting for known-vulnerable C extension CVEs
  8. Ruzzy + LibAFL harness template generation for identified attack surfaces

  AI auto-trigger conditions:
  - HTTP headers reveal Ruby/Rails/Sinatra
  - X-Powered-By or Server contains Ruby version
  - Response bodies contain Ruby stack traces
  - File upload endpoints accepting binary formats
  - Known Ruby CMS signatures (Redmine, Discourse, GitLab CE, Spree)

Evidence levels:
  VERIFIED   — Ruby framework confirmed + C extension parser endpoint found + version leak
  LIKELY     — Ruby framework confirmed + parser endpoints found
  INFERRED   — Ruby headers detected, no parser surface confirmed
  AI_ANALYSIS — Response patterns suggest Ruby, no definitive confirmation

Fuzzing surface categories:
  HIGH_VALUE  — C extension parsers accepting attacker-controlled binary data
  MEDIUM_VALUE — Pure Ruby parsers (slower, less crash-prone, but logic bugs)
  LOW_VALUE   — Static endpoints with minimal parsing
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException


# ── Ruby framework fingerprints ───────────────────────────────────────────────

RUBY_FRAMEWORK_HEADERS = {
    "X-Powered-By": [
        (re.compile(r"Phusion Passenger", re.I), "rails_passenger"),
        (re.compile(r"Rack", re.I),              "rack_generic"),
    ],
    "Server": [
        (re.compile(r"Passenger",  re.I), "rails_passenger"),
        (re.compile(r"Puma",       re.I), "rails_puma"),
        (re.compile(r"Unicorn",    re.I), "rails_unicorn"),
        (re.compile(r"Thin",       re.I), "sinatra_thin"),
        (re.compile(r"WEBrick",    re.I), "webrick"),
    ],
}

# Cookies that indicate Ruby frameworks
RUBY_COOKIE_PATTERNS = [
    re.compile(r"_session_id",      re.I),   # Rails
    re.compile(r"rack\.session",    re.I),   # Rack
    re.compile(r"sinatra\.",        re.I),   # Sinatra
]

# Response body patterns revealing Ruby framework
RUBY_BODY_PATTERNS = [
    (re.compile(r"ActionController::RoutingError",    re.I), "rails",   "critical"),
    (re.compile(r"ActionView::Template::Error",        re.I), "rails",   "critical"),
    (re.compile(r"ActiveRecord::",                     re.I), "rails",   "critical"),
    (re.compile(r"Sinatra::NotFound",                  re.I), "sinatra", "critical"),
    (re.compile(r"Rack::Lint::LintError",              re.I), "rack",    "high"),
    (re.compile(r"app/controllers/.*\.rb",             re.I), "rails",   "high"),
    (re.compile(r"app/models/.*\.rb",                  re.I), "rails",   "high"),
    (re.compile(r"Bundler::GemNotFound",               re.I), "ruby",    "medium"),
    (re.compile(r"Ruby\s+\d+\.\d+\.\d+",              re.I), "ruby",    "medium"),
    (re.compile(r"/usr/local/lib/ruby/gems/",          re.I), "ruby",    "high"),
    (re.compile(r"(app|lib)/.*\.rb:\d+:in",            re.I), "ruby",    "high"),
]

# Known Ruby CMS / apps
RUBY_CMS_URL_PATTERNS = [
    (re.compile(r"/redmine",    re.I), "Redmine"),
    (re.compile(r"/gitlab",     re.I), "GitLab CE"),
    (re.compile(r"/discourse",  re.I), "Discourse"),
    (re.compile(r"/spree",      re.I), "Spree Commerce"),
    (re.compile(r"/solidus",    re.I), "Solidus"),
    (re.compile(r"/refinery",   re.I), "RefineryCMS"),
]

# ── Ruby C extension parser endpoints ────────────────────────────────────────

PARSER_ENDPOINT_PATHS = [
    # JSON endpoints
    ("/api/v1",         "json",        "oj/json"),
    ("/api/v2",         "json",        "oj/json"),
    ("/api",            "json",        "oj/json"),
    ("/graphql",        "graphql",     "graphql-ruby/libgraphqlparser"),
    # File upload / binary processing
    ("/upload",         "multipart",   "file_upload"),
    ("/uploads",        "multipart",   "file_upload"),
    ("/attachments",    "multipart",   "file_upload"),
    ("/files",          "multipart",   "file_upload"),
    ("/image",          "multipart",   "rmagick/mini_magick"),
    ("/images",         "multipart",   "rmagick/mini_magick"),
    ("/avatar",         "multipart",   "rmagick/mini_magick"),
    ("/thumbnail",      "multipart",   "rmagick/mini_magick"),
    # XML / HTML parsing
    ("/sitemap.xml",    "xml",         "nokogiri"),
    ("/feed",           "xml",         "nokogiri"),
    ("/rss",            "xml",         "nokogiri"),
    ("/atom",           "xml",         "nokogiri"),
    # YAML (dangerous if Psych loaded without safe_load)
    ("/config",         "yaml",        "psych"),
    ("/settings",       "yaml",        "psych"),
    # MessagePack / Protobuf (binary)
    ("/msgpack",        "msgpack",     "msgpack-ruby C ext"),
    ("/proto",          "protobuf",    "google-protobuf C ext"),
    ("/metrics",        "protobuf",    "google-protobuf C ext"),
]

CONTENT_TYPE_C_EXT_MAP = {
    "application/json":              ("json",     "oj / Oj C extension",           "HIGH_VALUE"),
    "application/graphql":           ("graphql",  "graphql-ruby libgraphqlparser",  "HIGH_VALUE"),
    "multipart/form-data":           ("file",     "file upload → C ext pipeline",   "HIGH_VALUE"),
    "application/x-msgpack":         ("msgpack",  "msgpack-ruby C extension",       "HIGH_VALUE"),
    "application/protobuf":          ("protobuf", "google-protobuf C extension",    "HIGH_VALUE"),
    "application/x-protobuf":        ("protobuf", "google-protobuf C extension",    "HIGH_VALUE"),
    "application/xml":               ("xml",      "nokogiri C extension",           "HIGH_VALUE"),
    "text/xml":                      ("xml",      "nokogiri C extension",           "HIGH_VALUE"),
    "application/x-www-form-urlencoded": ("form", "Rack / URI C parser",           "MEDIUM_VALUE"),
    "text/csv":                      ("csv",      "CSV stdlib / C layer",           "MEDIUM_VALUE"),
    "application/yaml":              ("yaml",     "Psych C extension",              "MEDIUM_VALUE"),
    "text/yaml":                     ("yaml",     "Psych C extension",              "MEDIUM_VALUE"),
}

# ── YAML unsafe load detection patterns ──────────────────────────────────────

YAML_UNSAFE_PATTERNS = [
    re.compile(r"YAML\.load\b(?!_file|_stream)",     re.I),   # YAML.load (unsafe)
    re.compile(r"Psych\.load\b(?!_file|_stream)",    re.I),   # Psych.load (unsafe)
    re.compile(r"YAML\.unsafe_load",                 re.I),
]

# ── Gem version leak patterns ─────────────────────────────────────────────────

GEM_VERSION_RE = re.compile(
    r"(rails|sinatra|nokogiri|oj|rack|puma|unicorn|passenger|grape|hanami)[/\s]+v?(\d+\.\d+[\.\d]*)",
    re.IGNORECASE,
)

# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class RubyFuzzSurface:
    surface_type: str       # "c_ext_parser" | "file_upload" | "graphql" | "yaml_unsafe"
                            # | "framework_detected" | "gem_version_leak" | "binary_endpoint"
    description: str
    url: str = ""
    http_method: str = "GET"
    content_type: str = ""
    c_extension: str = ""
    framework: str = ""
    gem_version: str = ""
    fuzz_value: str = "HIGH_VALUE"  # HIGH_VALUE | MEDIUM_VALUE | LOW_VALUE
    evidence_level: str = "AI_ANALYSIS"
    severity: str = "medium"
    ruzzy_harness: str = ""         # generated harness snippet
    curl_poc: str = ""
    remediation_hint: str = ""


@dataclass
class RubyLibAFLResult:
    target: str
    surfaces: list[RubyFuzzSurface] = field(default_factory=list)
    framework: str = ""
    framework_version: str = ""
    ruby_version: str = ""
    high_value_surfaces: int = 0
    medium_value_surfaces: int = 0
    c_ext_parsers_found: list[str] = field(default_factory=list)
    yaml_unsafe_risk: bool = False
    graphql_endpoint: str = ""
    file_upload_endpoints: list[str] = field(default_factory=list)
    gem_versions: dict = field(default_factory=dict)
    severity: str = "none"
    evidence_level: str = "AI_ANALYSIS"
    error: str = ""
    summary: str = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class RubyLibAFLFuzzScanner:
    """
    Detects Ruby-based web application attack surfaces suitable for
    coverage-guided fuzzing with Ruzzy + LibAFL:
      1. Ruby framework detection (headers, cookies, body patterns)
      2. C extension parser endpoint discovery
      3. Binary/structured data deserialization surface mapping
      4. YAML unsafe load risk patterns
      5. Ruzzy harness snippet generation for discovered surfaces
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    TIMEOUT = 8

    def __init__(
        self,
        target: str,
        proxies: Optional[dict] = None,
    ):
        self.target = target.rstrip("/")
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self.session.verify = False

    # ── Public entry ──────────────────────────────────────────────────────────

    def scan(self) -> RubyLibAFLResult:
        result = RubyLibAFLResult(target=self.target)
        try:
            base_resp = self._get(self.target)
            if base_resp:
                self._detect_framework_headers(result, base_resp)
                self._detect_framework_body(result, base_resp)
                self._detect_gem_versions(result, base_resp)

            if result.framework or self._looks_like_ruby_cms():
                self._probe_parser_endpoints(result)
                self._probe_graphql(result)
                self._check_yaml_risk(result)
                self._probe_error_disclosure(result)

            self._compute_severity(result)
            self._build_summary(result)
        except Exception as exc:
            result.error = str(exc)
        return result

    # ── Framework detection ───────────────────────────────────────────────────

    def _detect_framework_headers(self, result: RubyLibAFLResult, resp) -> None:
        for header, patterns in RUBY_FRAMEWORK_HEADERS.items():
            value = resp.headers.get(header, "")
            if not value:
                continue
            for pattern, fw_type in patterns:
                if pattern.search(value):
                    result.framework = fw_type
                    surface = RubyFuzzSurface(
                        surface_type="framework_detected",
                        description=(
                            f"Ruby framework detected via {header} header: "
                            f"{value[:80]} → {fw_type}"
                        ),
                        url=self.target,
                        framework=fw_type,
                        fuzz_value="MEDIUM_VALUE",
                        evidence_level="LIKELY",
                        severity="info",
                        remediation_hint=(
                            "Remove framework/server version from HTTP headers. "
                            "Deploy Ruzzy+LibAFL fuzzing against parser endpoints."
                        ),
                    )
                    result.surfaces.append(surface)
                    break

        # Cookie-based detection
        for cookie_name in resp.cookies:
            for pattern in RUBY_COOKIE_PATTERNS:
                if pattern.search(cookie_name):
                    if not result.framework:
                        result.framework = "rack_ruby"
                    break

        # Ruby version from headers
        for header in ["X-Ruby-Version", "X-Powered-By", "Server"]:
            val = resp.headers.get(header, "")
            m = re.search(r"Ruby[/\s]+([\d.]+)", val, re.I)
            if m:
                result.ruby_version = m.group(1)

    def _detect_framework_body(self, result: RubyLibAFLResult, resp) -> None:
        body = resp.text[:8000]
        for pattern, framework, sev in RUBY_BODY_PATTERNS:
            m = pattern.search(body)
            if m:
                if not result.framework:
                    result.framework = framework
                surface = RubyFuzzSurface(
                    surface_type="framework_detected",
                    description=(
                        f"Ruby stack trace / error disclosure in response body: "
                        f"'{m.group(0)[:80]}'"
                    ),
                    url=self.target,
                    framework=framework,
                    fuzz_value="MEDIUM_VALUE",
                    evidence_level="VERIFIED" if sev == "critical" else "LIKELY",
                    severity=sev,
                    curl_poc=f"curl -sk '{self.target}'",
                    remediation_hint=(
                        "Disable detailed error responses in production "
                        "(config.consider_all_requests_local = false in Rails). "
                        "Do not expose Ruby backtraces to clients."
                    ),
                )
                result.surfaces.append(surface)
                break  # one body match is enough

        # Gem version extraction from body
        for m in GEM_VERSION_RE.finditer(body):
            gem, ver = m.group(1).lower(), m.group(2)
            result.gem_versions[gem] = ver
            if not result.framework_version and gem in ("rails", "sinatra", "hanami"):
                result.framework_version = ver

    def _detect_gem_versions(self, result: RubyLibAFLResult, resp) -> None:
        for header in resp.headers:
            m = GEM_VERSION_RE.search(resp.headers[header])
            if m:
                gem, ver = m.group(1).lower(), m.group(2)
                result.gem_versions[gem] = ver
                surface = RubyFuzzSurface(
                    surface_type="gem_version_leak",
                    description=(
                        f"Gem version leaked in header '{header}': {gem} {ver}"
                    ),
                    url=self.target,
                    gem_version=f"{gem}/{ver}",
                    fuzz_value="LOW_VALUE",
                    evidence_level="VERIFIED",
                    severity="low",
                    remediation_hint=(
                        f"Remove gem/framework version from HTTP response headers."
                    ),
                )
                result.surfaces.append(surface)

    # ── Parser endpoint discovery ─────────────────────────────────────────────

    def _probe_parser_endpoints(self, result: RubyLibAFLResult) -> None:
        for path, data_type, c_ext in PARSER_ENDPOINT_PATHS:
            url = self.target + path
            resp = self._get(url)
            if not resp:
                continue
            if resp.status_code in (200, 201, 400, 401, 403, 405, 422):
                ct = resp.headers.get("Content-Type", "").lower()
                fuzz_val = "HIGH_VALUE" if data_type in (
                    "graphql", "msgpack", "protobuf", "xml", "multipart"
                ) else "MEDIUM_VALUE"

                if data_type == "multipart" and resp.status_code in (200, 201, 400, 405, 422):
                    result.file_upload_endpoints.append(url)

                surface = RubyFuzzSurface(
                    surface_type="c_ext_parser",
                    description=(
                        f"Parser endpoint [{data_type}] reachable at {path} "
                        f"(status:{resp.status_code}) — C extension: {c_ext}"
                    ),
                    url=url,
                    http_method="POST" if data_type in ("multipart", "json", "xml") else "GET",
                    content_type=ct,
                    c_extension=c_ext,
                    fuzz_value=fuzz_val,
                    evidence_level="LIKELY" if resp.status_code in (200, 201) else "INFERRED",
                    severity="medium" if fuzz_val == "HIGH_VALUE" else "low",
                    ruzzy_harness=self._generate_harness(url, data_type, c_ext),
                    curl_poc=self._build_curl_poc(url, data_type),
                    remediation_hint=(
                        f"Fuzz this endpoint with Ruzzy+LibAFL targeting {c_ext} parser. "
                        "Validate and sanitize all input before passing to C extension."
                    ),
                )
                result.surfaces.append(surface)

                if c_ext not in result.c_ext_parsers_found:
                    result.c_ext_parsers_found.append(c_ext)
                if fuzz_val == "HIGH_VALUE":
                    result.high_value_surfaces += 1
                else:
                    result.medium_value_surfaces += 1

                # Content-type based classification override
                for ct_prefix, (dtype2, cext2, fval2) in CONTENT_TYPE_C_EXT_MAP.items():
                    if ct_prefix in ct and cext2 not in result.c_ext_parsers_found:
                        result.c_ext_parsers_found.append(cext2)
                        break

    # ── GraphQL endpoint ──────────────────────────────────────────────────────

    def _probe_graphql(self, result: RubyLibAFLResult) -> None:
        for path in ["/graphql", "/api/graphql", "/graphiql", "/api/v1/graphql"]:
            url = self.target + path
            # Probe with introspection
            try:
                resp = self.session.post(
                    url,
                    json={"query": "{ __typename }"},
                    timeout=self.TIMEOUT,
                    proxies=self.proxies,
                    headers={"Content-Type": "application/json"},
                )
            except RequestException:
                continue

            if resp.status_code in (200, 400) and (
                "data" in resp.text or "errors" in resp.text or "__typename" in resp.text
            ):
                result.graphql_endpoint = url
                surface = RubyFuzzSurface(
                    surface_type="c_ext_parser",
                    description=(
                        f"GraphQL endpoint confirmed at {url} — "
                        "graphql-ruby uses libgraphqlparser C extension for query parsing"
                    ),
                    url=url,
                    http_method="POST",
                    content_type="application/json",
                    c_extension="graphql-ruby / libgraphqlparser",
                    fuzz_value="HIGH_VALUE",
                    evidence_level="VERIFIED",
                    severity="high",
                    ruzzy_harness=self._generate_harness(url, "graphql", "libgraphqlparser"),
                    curl_poc=(
                        f'curl -sk -X POST {url} '
                        f'-H "Content-Type: application/json" '
                        f'-d \'{{"query":"{{__typename}}"}}\'',
                    ),
                    remediation_hint=(
                        "Fuzz with Ruzzy+LibAFL: feed malformed GraphQL queries to "
                        "graphql-ruby parser. Enable query depth/complexity limits."
                    ),
                )
                result.surfaces.append(surface)
                result.c_ext_parsers_found.append("libgraphqlparser")
                result.high_value_surfaces += 1
                break

    # ── YAML unsafe load risk ─────────────────────────────────────────────────

    def _check_yaml_risk(self, result: RubyLibAFLResult) -> None:
        """Check for YAML deserialization endpoints (risk: unsafe Psych.load)."""
        for path in ["/import", "/load", "/restore", "/data", "/config/import"]:
            url = self.target + path
            resp = self._get(url)
            if not resp:
                continue
            if resp.status_code in (200, 400, 405, 422):
                ct = resp.headers.get("Content-Type", "").lower()
                if "yaml" in ct or "yml" in ct:
                    result.yaml_unsafe_risk = True
                    surface = RubyFuzzSurface(
                        surface_type="yaml_unsafe",
                        description=(
                            f"YAML endpoint at {url} (status:{resp.status_code}) — "
                            "risk: Psych.load (unsafe) enables Ruby object deserialization. "
                            "Use YAML.safe_load / Psych.safe_load instead."
                        ),
                        url=url,
                        content_type=ct,
                        c_extension="Psych (Ruby Psych C extension)",
                        fuzz_value="HIGH_VALUE",
                        evidence_level="LIKELY",
                        severity="high",
                        curl_poc=(
                            f'curl -sk -X POST {url} '
                            f'-H "Content-Type: application/yaml" '
                            f'-d "--- !!ruby/object:Gem::Installer \'a\'"'
                        ),
                        remediation_hint=(
                            "Replace YAML.load / Psych.load with YAML.safe_load / "
                            "Psych.safe_load to prevent object deserialization. "
                            "Fuzz with Ruzzy+LibAFL targeting Psych C extension."
                        ),
                    )
                    result.surfaces.append(surface)
                    result.c_ext_parsers_found.append("Psych C extension")
                    result.high_value_surfaces += 1

    # ── Error disclosure ──────────────────────────────────────────────────────

    def _probe_error_disclosure(self, result: RubyLibAFLResult) -> None:
        """Send malformed requests to trigger Ruby error disclosure."""
        for url in [self.target + "/nonexistent-ruby-fuzz-probe-404"]:
            resp = self._get(url)
            if not resp:
                continue
            body = resp.text[:3000]
            for pattern, framework, sev in RUBY_BODY_PATTERNS:
                if pattern.search(body) and sev in ("critical", "high"):
                    if not result.framework:
                        result.framework = framework
                    surface = RubyFuzzSurface(
                        surface_type="framework_detected",
                        description=(
                            f"Ruby error disclosure on 404 path — "
                            f"framework: {framework}"
                        ),
                        url=url,
                        framework=framework,
                        fuzz_value="LOW_VALUE",
                        evidence_level="VERIFIED",
                        severity="medium",
                        remediation_hint="Disable detailed error pages in production.",
                    )
                    result.surfaces.append(surface)
                    break

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _looks_like_ruby_cms(self) -> bool:
        for pattern, _ in RUBY_CMS_URL_PATTERNS:
            if pattern.search(self.target):
                return True
        return False

    def _get(self, url: str):
        try:
            return self.session.get(
                url, timeout=self.TIMEOUT, proxies=self.proxies, allow_redirects=True
            )
        except RequestException:
            return None

    def _generate_harness(self, url: str, data_type: str, c_ext: str) -> str:
        """Generate a minimal Ruzzy harness snippet for the identified surface."""
        if data_type == "graphql":
            return (
                "# Ruzzy+LibAFL harness for GraphQL parser\n"
                "# Run: FUZZER_NO_MAIN_LIB=/usr/lib/libFuzzer.a LD=lld ruzzy fuzz harness.rb\n"
                "require 'graphql'\n\n"
                "Ruzzy.fuzz do |data|\n"
                "  begin\n"
                "    GraphQL.parse(data.to_s)\n"
                "  rescue GraphQL::ParseError\n"
                "    # expected\n"
                "  end\n"
                "end\n"
            )
        elif data_type in ("xml",):
            return (
                "# Ruzzy+LibAFL harness for Nokogiri XML parser\n"
                "require 'nokogiri'\n\n"
                "Ruzzy.fuzz do |data|\n"
                "  begin\n"
                "    Nokogiri::XML(data.to_s) { |c| c.strict }\n"
                "  rescue Nokogiri::XML::SyntaxError\n"
                "    # expected\n"
                "  end\n"
                "end\n"
            )
        elif data_type == "json":
            return (
                "# Ruzzy+LibAFL harness for Oj JSON parser\n"
                "require 'oj'\n\n"
                "Ruzzy.fuzz do |data|\n"
                "  begin\n"
                "    Oj.load(data.to_s)\n"
                "  rescue Oj::ParseError, EncodingError\n"
                "    # expected\n"
                "  end\n"
                "end\n"
            )
        elif data_type == "msgpack":
            return (
                "# Ruzzy+LibAFL harness for MessagePack C extension\n"
                "require 'msgpack'\n\n"
                "Ruzzy.fuzz do |data|\n"
                "  begin\n"
                "    MessagePack.unpack(data)\n"
                "  rescue MessagePack::UnpackError, RangeError\n"
                "    # expected\n"
                "  end\n"
                "end\n"
            )
        elif data_type in ("multipart", "file"):
            return (
                "# Ruzzy+LibAFL harness for file upload C ext pipeline\n"
                "# Adjust to match your image/document processing library\n"
                "require 'mini_magick'  # or rmagick\n\n"
                "Ruzzy.fuzz do |data|\n"
                "  Tempfile.create(['fuzz', '.bin']) do |f|\n"
                "    f.write(data)\n"
                "    f.flush\n"
                "    begin\n"
                "      MiniMagick::Image.open(f.path)\n"
                "    rescue MiniMagick::Error, MiniMagick::Invalid\n"
                "      # expected\n"
                "    end\n"
                "  end\n"
                "end\n"
            )
        else:
            return (
                f"# Ruzzy+LibAFL harness for {c_ext}\n"
                "Ruzzy.fuzz do |data|\n"
                "  # TODO: feed data to target C extension parser\n"
                "end\n"
            )

    def _build_curl_poc(self, url: str, data_type: str) -> str:
        if data_type == "json":
            return f'curl -sk -X POST {url} -H "Content-Type: application/json" -d \'{{"fuzz":"test"}}\''
        elif data_type in ("multipart", "file"):
            return f'curl -sk -X POST {url} -F "file=@test.bin"'
        elif data_type == "xml":
            return f'curl -sk -X POST {url} -H "Content-Type: application/xml" -d "<fuzz/>"'
        elif data_type == "yaml":
            return f'curl -sk -X POST {url} -H "Content-Type: application/yaml" -d "fuzz: test"'
        elif data_type == "msgpack":
            return f'curl -sk -X POST {url} -H "Content-Type: application/x-msgpack" --data-binary @payload.msgpack'
        else:
            return f"curl -sk '{url}'"

    def _compute_severity(self, result: RubyLibAFLResult) -> None:
        ev_set = {s.evidence_level for s in result.surfaces}
        if result.high_value_surfaces >= 3 and "VERIFIED" in ev_set:
            result.severity = "high"
            result.evidence_level = "VERIFIED"
        elif result.high_value_surfaces >= 1 or "VERIFIED" in ev_set:
            result.severity = "medium"
            result.evidence_level = "LIKELY" if "VERIFIED" not in ev_set else "VERIFIED"
        elif result.surfaces:
            result.severity = "low"
            result.evidence_level = "INFERRED"
        else:
            result.severity = "none"

    def _build_summary(self, result: RubyLibAFLResult) -> None:
        result.summary = (
            f"RubyLibAFLFuzz: {len(result.surfaces)} surfaces | "
            f"framework:{result.framework or 'unknown'} | "
            f"C-ext parsers:{len(result.c_ext_parsers_found)} | "
            f"high-value:{result.high_value_surfaces} | "
            f"medium-value:{result.medium_value_surfaces} | "
            f"graphql:{bool(result.graphql_endpoint)} | "
            f"yaml_risk:{result.yaml_unsafe_risk} | "
            f"file_uploads:{len(result.file_upload_endpoints)} | "
            f"severity:{result.severity}"
        )
