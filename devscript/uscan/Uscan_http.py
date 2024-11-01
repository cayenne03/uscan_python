import re
import requests
from urllib.parse import urlparse, urljoin, urlunparse
import UscanOutput
import UscanUtils
import Uscan_xtp


class Uscan_http:
    def __init__(self, downloader, parse_result, headers, watchfile, line, shared):
        self.downloader = downloader
        self.parse_result = parse_result
        self.headers = headers
        self.watchfile = watchfile
        self.line = line
        self.shared = shared
        self.patterns = []
        self.sites = []
        self.basedirs = []

    def handle_redirection(self, pattern, additional_bases=None):
        additional_bases = additional_bases or []
        redirections = self.downloader.get_redirections()
        patterns, base_sites, base_dirs = [], [], []

        if redirections:
            UscanOutput.uscan_verbose(f"redirections: {redirections}")

        for redirect in redirections + additional_bases:
            base_dir = re.sub(r'^\w+://[^/]+/', '/', redirect)
            base_dir = re.sub(r'/[^/]*(?:[#?].*)?$', '/', base_dir)

            base_site_match = re.match(r'^(\w+://[^/]+)', redirect)
            if base_site_match:
                base_site = base_site_match.group(1)
                patterns.append(re.escape(base_site) + re.escape(base_dir) + pattern)
                base_sites.append(base_site)
                base_dirs.append(base_dir)

                # Remove the filename from base_dir if necessary
                base_dir_orig = base_dir
                base_dir = re.sub(r'/[^/]*$', '/', base_dir)
                if base_dir != base_dir_orig:
                    patterns.append(re.escape(base_site) + re.escape(base_dir) + pattern)
                    base_sites.append(base_site)
                    base_dirs.append(base_dir)

        return patterns, base_sites, base_dirs

    def http_search(self):
        if self.parse_result.get("base").startswith("https") and not self.downloader.ssl_enabled():
            UscanOutput.uscan_die(
                "The liblwp-protocol-https-perl package must be installed to use https URLs"
            )

        UscanOutput.uscan_verbose(f"Requesting URL: {self.parse_result.get('base')}")
        request = requests.Request("GET", self.parse_result.get("base"))

        # Set headers
        for key, value in self.downloader.headers.items():
            base_url, hdr = key.split('@', 1)
            if re.match(rf'^{re.escape(base_url)}(?:/.*)?$', self.parse_result.get("base")):
                request.headers[hdr] = value
                UscanOutput.uscan_verbose(f"Set per-host custom header {hdr} for {self.parse_result.get('base')}")
            else:
                UscanOutput.uscan_debug(f"{self.parse_result.get('base')} does not start with {base_url}")

        request.headers.update({"Accept-Encoding": "gzip", "Accept": "*/*"})

        session = requests.Session()
        response = session.send(session.prepare_request(request))

        if not response.ok:
            UscanOutput.uscan_warn(
                f"In watchfile {self.watchfile}, reading webpage {self.parse_result.get('base')} failed: "
                + response.reason
            )
            return None

        patterns, base_sites, base_dirs = self.handle_redirection(self.parse_result.get("filepattern"))
        self.patterns.extend(patterns)
        self.sites.extend(base_sites)
        self.basedirs.extend(base_dirs)

        content = response.text
        UscanOutput.uscan_extra_debug(f"Received content:\n{content}\n[End of received content] by HTTP")

        if not self.parse_result.get("searchmode") or self.parse_result.get("searchmode") == "html":
            hrefs = self.html_search(content, self.patterns)
        elif self.parse_result.get("searchmode") == "plain":
            hrefs = self.plain_search(content)
        else:
            UscanOutput.uscan_warn(f'Unknown searchmode "{self.parse_result.get("searchmode")}", skipping')
            return None

        if hrefs:
            hrefs = sorted(hrefs, key=lambda x: x[0], reverse=True)
            msg = "Found the following matching hrefs on the web page (newest first):\n"
            for href in hrefs:
                msg += f"   {href[2]} ({href[1]}) index={href[0]} {href[3]}\n"
            UscanOutput.uscan_verbose(msg)

        newversion, newfile = None, None
        if self.shared.get("download_version") and not self.parse_result.get("versionmode") == "ignore":
            vhrefs = [href for href in hrefs if href[3]]
            if vhrefs:
                _, newversion, newfile, _ = vhrefs[0]
            else:
                UscanOutput.uscan_warn(
                    f"In {self.watchfile} no matching hrefs for version {self.shared['download_version']} "
                    + f"in watch line {self.line}"
                )
                return None
        else:
            if hrefs:
                _, newversion, newfile, _ = hrefs[0]
            else:
                UscanOutput.uscan_warn(
                    f"In {self.watchfile} no matching files for watch line {self.line}"
                )
                return None

        return newversion, newfile

    def http_upstream_url(self):
        newfile = self.parse_result.get("newfile")

        if newfile.startswith("http://") or newfile.startswith("https://"):
            upstream_url = newfile
        elif newfile.startswith("//"):
            upstream_url = self.parse_result.get("site")
            scheme = urlparse(upstream_url).scheme
            upstream_url = f"{scheme}:{newfile}"
        elif newfile.startswith("/"):
            if len(self.patterns) > 1:
                for i in range(len(self.patterns)):
                    if re.match(rf"^{self.patterns[i]}", f"{self.sites[i]}{newfile}"):
                        upstream_url = f"{self.sites[i]}{newfile}"
                        break
                else:
                    UscanOutput.uscan_verbose(
                        "Unable to determine upstream url from redirections, "
                        "defaulting to using site specified in watch file"
                    )
                    upstream_url = f"{self.sites[0]}{newfile}"
            else:
                upstream_url = f"{self.sites[0]}{newfile}"
        else:
            if len(self.patterns) > 1:
                for i in range(len(self.patterns)):
                    if self.basedirs[i].endswith('/'):
                        nf = f"{self.basedirs[i]}{newfile}"
                        if re.match(rf"^{self.patterns[i]}", f"{self.sites[i]}{nf}"):
                            upstream_url = f"{self.sites[i]}{nf}"
                            break
                else:
                    UscanOutput.uscan_verbose(
                        "Unable to determine upstream url from redirections, "
                        "defaulting to using site specified in watch file"
                    )
                    upstream_url = f"{self.parse_result.get('urlbase')}{newfile}"
            else:
                upstream_url = f"{self.parse_result.get('urlbase')}{newfile}"

        upstream_url = upstream_url.replace("&amp;", "&")
        UscanOutput.uscan_verbose(f"Matching target for downloadurlmangle: {upstream_url}")

        if self.parse_result.get("downloadurlmangle"):
            if UscanUtils.mangle(self.watchfile, self.line, "downloadurlmangle:",
                                 self.parse_result["downloadurlmangle"], upstream_url):
                self.status = 1
                return None
        return upstream_url

    def http_newdir(self, https, line, site, dir, pattern, dirversionmangle, watchfile, lineptr, download_version):
        session = requests.Session()
        base = site + dir
        short_versions = Uscan_xtp.partial_version(download_version)

        if https and not self.downloader.ssl_enabled():
            UscanOutput.uscan_die(
                "You must have the SSL package installed to use https URLs"
            )

        UscanOutput.uscan_verbose(f"Requesting URL: {base}")
        response = session.get(base)

        if not response.ok:
            UscanOutput.uscan_warn(
                f"In watch file {watchfile}, reading webpage {base} failed: {response.reason}"
            )
            return ''

        content = response.content
        if response.headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                content = response.content.decode("gzip")
            except Exception as e:
                UscanOutput.uscan_warn(f"Unable to decode remote content: {str(e)}")
                return ''

        UscanOutput.uscan_extra_debug(
            f"Received content:\n{content.decode()}\n[End of received content] by HTTP"
        )

        content = self.clean_content(content.decode())

        dirpatterns, base_sites, base_dirs = self.handle_redirection(line, pattern, base)
        self.downloader.clear_redirections()

        hrefs = []
        for parsed in self.html_search(content, dirpatterns, 'dirversionmangle'):
            priority, mangled_version, href, match = parsed
            match_description = self.match_download_version(
                mangled_version, download_version, short_versions
            )
            hrefs.append((mangled_version, href, match_description))

        # Extract only matched hrefs
        matched_hrefs = [href for href in hrefs if href[2]]
        if matched_hrefs:
            matched_hrefs = sorted(matched_hrefs, key=lambda x: x[0], reverse=True)
            newdir = matched_hrefs[0][1]
        else:
            UscanOutput.uscan_warn(f"No matching hrefs for pattern in {watchfile}: {site}{dir}{pattern}")
            return ''

        # Only return the final directory component
        newdir = newdir.rstrip('/').split('/')[-1]
        return newdir

    def handle_redirection(self, line, pattern, base):
        patterns, base_sites, base_dirs = [], [], []
        for redirection in self.downloader.get_redirections():
            base_dir = re.sub(r'^\w+://[^/]+/', '/', redirection)
            base_dir = re.sub(r'/[^/]*(?:[#?].*)?$', '/', base_dir)

            base_site_match = re.match(r'^(\w+://[^/]+)', redirection)
            if base_site_match:
                base_site = base_site_match.group(1)
                patterns.append(re.escape(base_site) + re.escape(base_dir) + pattern)
                base_sites.append(base_site)
                base_dirs.append(base_dir)

        return patterns, base_sites, base_dirs

    def clean_content(self, content):
        # Fix unquoted href attributes
        content = re.sub(r'href\s*=\s*([^\s>]+)', r'href="\1"', content, flags=re.IGNORECASE)
        # Remove HTML comments
        content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
        return content

    def url_canonicalize_dots(self, base, url):
        parsed_url = urlparse(urljoin(base, url))
        path_parts = parsed_url.path.split('/')
        canonicalized_path = []
        for part in path_parts:
            if part == '..':
                if canonicalized_path:
                    canonicalized_path.pop()
            elif part != '.' and part:
                canonicalized_path.append(part)
        return urlunparse(parsed_url._replace(path='/'.join(canonicalized_path)))

    def html_search(self, content, patterns, mangle):
        # Modify content if pagemangle is specified
        if self.parse_result.get("pagemangle"):
            UscanUtils.mangle(
                self.watchfile, self.line, 'pagemangle:', self.parse_result["pagemangle"], content
            )

        base_match = re.search(r'<\s*base\s+[^>]*href\s*=\s*["\'](.*?)["\']', content, re.IGNORECASE)
        self.parse_result['urlbase'] = self.url_canonicalize_dots(self.parse_result['base'],
                                                                  base_match.group(1)) if base_match else \
        self.parse_result['base']

        hrefs = []
        for match in re.finditer(r'<\s*a\s+[^>]*(?<=\s)href\s*=\s*["\'](.*?)["\']', content, re.IGNORECASE):
            href = UscanUtils.fix_href(match.group(1))
            href_canonical = self.url_canonicalize_dots(self.parse_result['urlbase'], href)

            for pattern in patterns:
                if re.fullmatch(pattern, href) or re.fullmatch(pattern, href_canonical):
                    hrefs.append(self.parse_href(href_canonical, pattern, mangle))
        return hrefs

    def parse_href(self, href, pattern, mangle):
        mangled_version = ""
        if not self.parse_result.get("versionless"):
            match = re.match(pattern, href)
            mangled_version = match.group(1) if match else ""

        if UscanUtils.mangle(self.watchfile, self.line, mangle + ":", self.parse_result[mangle], mangled_version):
            return None
        priority = f"{mangled_version}-{UscanUtils.get_priority(href)}"
        return priority, mangled_version, href, ""

    def match_download_version(self, mangled_version, download_version, short_versions):
        if mangled_version == download_version:
            return "matched with the download version"
        elif mangled_version == short_versions[2]:
            return "matched with the download version (partial 3)"
        elif mangled_version == short_versions[1]:
            return "matched with the download version (partial 2)"
        elif mangled_version == short_versions[0]:
            return "matched with the download version (partial 1)"
        return ""
