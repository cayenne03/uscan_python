from datetime import datetime
import os
import re
import subprocess
import shutil
import hashlib
import tempfile
import UscanOutput
import UscanUtils
from Keyring import UscanKeyring
from pathlib import Path

from packaging.version import parse as Version


class WatchLine:
    # Static class attribute to track already downloaded files
    already_downloaded = {}

    def __init__(self, shared, keyring, config, downloader, line, pkg, pkg_dir, pkg_version, watchfile, watch_version):
        # Required attributes
        self.shared = shared
        self.keyring = keyring
        self.config = config
        self.downloader = downloader
        self.line = line
        self.pkg = pkg
        self.pkg_dir = pkg_dir
        self.pkg_version = pkg_version
        self.watchfile = watchfile
        self.watch_version = watch_version

        # Config-based attributes
        self.repack = config.get('repack', False)
        self.safe = config.get('safe', False)
        self.symlink = config.get('symlink', False)
        self.versionmode = 'newer'

        # Additional file attributes
        self.destfile = None
        self.sigfile = None

        # Line options
        self.component = None
        self.ctype = None
        self.hrefdecode = None
        self.repacksuffix = None
        self.unzipopt = None
        self.searchmode = None
        self.dirversionmangle = []
        self.downloadurlmangle = []
        self.dversionmangle = []
        self.filenamemangle = []
        self.pagemangle = []
        self.oversionmangle = []
        self.oversionmanglepagemangle = []
        self.pgpsigurlmangle = []
        self.uversionmangle = []
        self.versionmangle = []

        # Compression
        self.compression = UscanUtils.get_compression(config.get('compression')) if config.get('compression') else None
        self.versionless = None

        # Internal attributes
        self.style = 'new'
        self.status = 0
        self.badversion = False
        self.signature_available = False
        self.must_download = False
        self.mangled_version = None
        self.sites = []
        self.basedirs = []
        self.patterns = []

        # Result attributes
        self.parse_result = {}
        self.search_result = {}
        self.force_repack = None
        self.type = None
        self.upstream_url = None
        self.newfile_base = None

        # Additional configurable attributes with defaults
        self.date = '%Y%m%d'
        self.decompress = False
        self.gitexport = 'default'
        self.gitmode = 'shallow'
        self.mode = 'LWP'
        self.pgpmode = 'default'
        self.pretty = '0.0~git%cd.%h'

        # Build-only attributes
        self.gitrepo_dir = f"{self.pkg}-temporary.$$" + (f".{self.component}" if self.component else "") + '.git'
        self.headers = {'X-uscan-features': 'enhanced-matching', 'Accept': '*/*'}

        # Minimum version, placeholder for other processing
        self.minversion = ''

    def process(self):
        """Executes the main process for parsing, searching, downloading, and cleaning."""
        # Parse, search, retrieve URL, determine base, compare versions, download, package, and clean up.
        return (
                self.parse() or
                self.search() or
                self.get_upstream_url() or
                self.get_newfile_base() or
                self.cmp_versions() or
                self.download_file_and_sig() or
                self.mkorigtargz() or
                self.clean()
        )

    def parse(self):
        """Parse the watch line and populate parse_result."""
        UscanOutput.uscan_debug(f"Parsing line: {self.line}")

        # Clear previous URL redirections
        self.downloader.user_agent.clear_redirections()

        # Begin parsing
        if self.watch_version == 1:
            self._parse_version_1()
        else:
            self._parse_version_2_3_4()
        return self.status

    def _parse_version_1(self):
        """Parse a version 1 watch line."""
        components = self.line.split(' ', 5)
        site, dir_path, filepattern, lastversion, action = components[:5]

        # Perform checks on extracted components
        if not lastversion or "(" in site or "(" in dir_path:
            UscanOutput.uscan_warn(
                f"There appears to be a version 2 format line in the version 1 watch file {self.watchfile}. "
                f"Skipping line: {self.line}")
            self.status = 1
            return

        # Default FTP prefix for version 1
        if "://" not in site:
            site = f"ftp://{site}"
            if "(" not in filepattern:
                filepattern = self._convert_wildcards_to_regex(filepattern)
                self.style = "old"
                UscanOutput.uscan_warn(f"Using very old style filename pattern in {self.watchfile}: {filepattern}")

        # Construct the base URL
        base = f"{site}/{dir_path}".replace('//', '/')
        site_match = re.match(r'^(\w+://[^/]+)', base)
        if site_match:
            site = site_match.group(1)

        pattern = filepattern

        # Validate the presence of a version delimiter
        if "(" not in filepattern:
            UscanOutput.uscan_warn(
                f"Filename pattern missing version delimiters in {self.watchfile}. Skipping: {self.line}")
            self.status = 1
            return

        # Populate parse results for further processing
        self.parse_result = {
            'base': base,
            'filepattern': filepattern,
            'lastversion': lastversion,
            'action': action,
            'site': site,
            'basedir': dir_path,
            'mangled_lastversion': lastversion,  # Placeholder for mangled version processing
            'pattern': pattern
        }

    def _parse_version_2_3_4(self):
        """Parse watch line formats for version 2, 3, and 4."""
        # Handle optional parameters and parse options
        if self.line.startswith("opts="):
            self._parse_options()

        # Parse base, file pattern, and last version
        base, filepattern, lastversion, action = (self.line.split(maxsplit=3) + [""])[:4]

        # Validate file pattern and version mode
        self._validate_lastversion(lastversion)
        self._validate_pattern(base, filepattern)

        # Populate parse results for further processing
        self.parse_result = {
            'base': base,
            'filepattern': filepattern,
            'lastversion': lastversion,
            'action': action,
            'site': base,  # Update for actual base path as needed
            'mangled_lastversion': lastversion,
            'pattern': filepattern
        }

    def _convert_wildcards_to_regex(self, filepattern):
        """Converts shell wildcards to regular expressions."""
        filepattern = re.sub(r"\?", ".", filepattern)
        filepattern = re.sub(r"\*", ".*", filepattern)
        filepattern = filepattern.replace(".", r"\.")
        return filepattern

    def _parse_options(self):
        """Parse line options if they exist."""
        match = re.match(r'^opts="?(.*?)"?\s+', self.line)
        if match:
            opts = match.group(1)
            self.line = self.line[match.end():].strip()  # Remove opts part from line
            for opt in opts.split(','):
                self._apply_option(opt.strip())

    def _apply_option(self, opt):
        """Apply each parsed option to the relevant attribute."""
        if opt in ["pasv", "passive"]:
            self.downloader.pasv = True
        elif opt == "active":
            self.downloader.pasv = False
        elif opt.startswith("compression="):
            _, comp = opt.split("=")
            self.compression = UscanUtils.get_compression(comp)
        else:
            UscanOutput.uscan_warn(f"Unrecognized option: {opt}")

    def _validate_lastversion(self, lastversion):
        """Sets and validates last version field."""
        if not lastversion:
            lastversion = self.pkg_version if self.pkg_version else ""
        if lastversion.lower() in ["ignore", "same", "prev"]:
            self.versionmode = lastversion.lower()

    def _validate_pattern(self, base, filepattern):
        """Validates the file pattern and modifies it if necessary."""
        if self.versionmode != "ignore" and "(" not in filepattern:
            UscanOutput.uscan_warn(
                f"Pattern missing version delimiters in {self.watchfile}. Skipping line: {self.line}")
            self.status = 1

    def search(self):
        """Search for a new version or file link on the remote site."""
        UscanOutput.uscan_debug("Starting search in line()")
        newversion, newfile = self._do('search')

        if not newversion or not newfile:
            self.status = 1
            return self.status

        UscanOutput.uscan_verbose(
            f"Base URL: {self.parse_result.get('base')}, "
            f"File Pattern: {self.parse_result.get('filepattern')}, "
            f"New File: {newfile}, New Version: {newversion}, "
            f"Last Version: {self.parse_result.get('mangled_lastversion')}"
        )

        self.search_result = {
            'newversion': newversion,
            'newfile': newfile,
        }

        if self.style == 'old':
            version_match = re.match(r'^\D*(\d+\.(?:\d+\.)*\d+)\D*$', newversion)
            if version_match:
                self.search_result['newversion'] = version_match.group(1)
            else:
                UscanOutput.uscan_warn(
                    f"Warning: Unable to determine a pure numeric version from filename '{newfile}'"
                )
                self.status = 1
        return self.status

    def get_upstream_url(self):
        """Form the upstream URL for downloading the new version file."""
        UscanOutput.uscan_debug("Running get_upstream_url()")

        if self.parse_result.get('site', '').startswith(('http://', 'https://')):
            self.mode = 'http' if self.mode not in ['git', 'svn'] else self.mode
        else:
            self.mode = self.mode or 'ftp'

        self.upstream_url = self._do('upstream_url')
        if self.status:
            return self.status

        UscanOutput.uscan_verbose(f"Upstream URL identified as: {self.upstream_url}")
        return self.status

    def get_newfile_base(self):
        """Determine the local filename for the new file based on mangling rules."""
        UscanOutput.uscan_debug("Running get_newfile_base()")
        self.newfile_base = self._do('newfile_base')
        if self.status:
            return self.status

        UscanOutput.uscan_verbose(
            f"Filename for downloaded file: {self.newfile_base}"
        )
        return self.status

    def cmp_versions(self):
        """Compare available and local versions."""
        UscanOutput.uscan_debug("Running cmp_versions()")
        mangled_lastversion = self.parse_result.get('mangled_lastversion')
        name = self.component or self.pkg

        if 'common_newversion' not in self.shared:
            self.shared['common_newversion'] = self.search_result['newversion']

        dehs_tags = {
            'debian-uversion': self.parse_result.get('lastversion'),
            'debian-mangled-uversion': mangled_lastversion,
            'upstream-version': self.search_result['newversion'],
            'upstream-url': self.upstream_url,
            'component-name': [],
            'component-upstream-version': []
        }

        mangled_ver = Version(mangled_lastversion)
        upstream_ver = Version(self.search_result['newversion'])
        compver = (
            'same' if mangled_ver == upstream_ver else
            'older' if mangled_ver > upstream_ver else
            'newer'
        )

        if self.versionmode == 'newer' and compver == 'newer':
            UscanOutput.uscan_msg(
                f"Newest version of {name} on remote site is {self.search_result['newversion']}, "
                f"local version is {self.parse_result['mangled_lastversion']}\n"
                f"Available for download from: {self.upstream_url}"
            )
            dehs_tags['status'] = "newer package available"
            self.shared['download'] = 1
        elif self.versionmode == 'newer' and compver == 'same':
            UscanOutput.uscan_verbose(
                f"Package {name} is up to date with upstream version: {self.search_result['newversion']}"
            )
            dehs_tags['status'] = "up to date"
            self.shared['download'] = 0
        elif self.versionmode == 'ignore':
            UscanOutput.uscan_msg(
                f"Package {name} on remote site version {self.search_result['newversion']} available for download"
            )
            dehs_tags['status'] = "package available"
        elif compver == 'older':
            UscanOutput.uscan_verbose(
                f"Only older version of {name} available on remote site: {self.search_result['newversion']}"
            )
            dehs_tags['status'] = "only older package available"
            self.shared['download'] = 0

        return 0

    def download_file_and_sig(self):
        """Download file and, if needed, associated signature files."""
        UscanOutput.uscan_debug("line: download_file_and_sig()")
        skip_git_vrfy = False

        # Check if download or signature is not required
        if not self.shared.get('download') or self.shared.get('signature') == -1:
            return 0

        # Configure downloader
        self.downloader.git_export_all(self.gitexport == 'all')

        download_available = False
        upstream_base = os.path.basename(self.upstream_url)
        sigfile_base = self.newfile_base

        # Check for duplicate file downloads
        if self.newfile_base in WatchLine.already_downloaded:
            UscanOutput.uscan_die(
                f"Already downloaded a file named {self.newfile_base}. Use filenamemangle to avoid this conflict."
            )
        WatchLine.already_downloaded[self.newfile_base] = True

        # Attempt to download the tarball if pgpmode is not 'previous'
        if self.pgpmode != 'previous':
            dest_path = os.path.join(self.config['destdir'], self.newfile_base)
            if self.shared.get('download') == 3 and os.path.exists(dest_path):
                UscanOutput.uscan_verbose(f"Overwriting existing file: {self.newfile_base}")
                download_available = self.downloader.download(
                    self.upstream_url, dest_path, self, self.parse_result.get('base'),
                    self.pkg_dir, self.pkg, self.mode
                )
                if download_available:
                    UscanOutput.dehs_verbose(f"Successfully downloaded package: {self.newfile_base}")
                else:
                    UscanOutput.dehs_verbose(f"Failed to download package: {upstream_base}")

            elif os.path.exists(dest_path):
                download_available = True
                UscanOutput.dehs_verbose(f"Using existing file: {self.newfile_base}")
                skip_git_vrfy = True

            elif self.shared.get('download') > 0:
                UscanOutput.uscan_verbose(f"Downloading package: {upstream_base}")
                download_available = self.downloader.download(
                    self.upstream_url, dest_path, self, self.parse_result.get('base'),
                    self.pkg_dir, self.pkg, self.mode, self.gitrepo_dir
                )
                if download_available:
                    UscanOutput.dehs_verbose(f"Downloaded upstream package: {upstream_base}")
                    if self.filenamemangle:
                        UscanOutput.dehs_verbose(f"Renamed package to: {self.newfile_base}")
                else:
                    UscanOutput.dehs_verbose(f"Failed to download package: {upstream_base}")
            else:
                UscanOutput.dehs_verbose(f"Skipping download for package: {upstream_base}")

        # PGP signature handling
        if self.pgpmode == 'self':
            sigfile_base = re.sub(r'^(.*?)\.[^.]+$', r'\1', sigfile_base)  # Strip extension
            if self.shared.get('signature') == -1:
                UscanOutput.uscan_warn("Skipping OpenPGP signature check by request.")
                download_available = -1
                self.signature_available = 0
            elif not self.keyring:
                UscanOutput.uscan_die("No keyring found for OpenPGP signature verification.")
            elif download_available == 0:
                UscanOutput.uscan_warn("No downloaded tarball available for signature verification.")
                return 1

            else:
                self.keyring.verify(
                    os.path.join(self.config['destdir'], sigfile_base),
                    os.path.join(self.config['destdir'], self.newfile_base)
                )
                self.signature_available = 3

        # Decompression if necessary
        if download_available == 1 and self.decompress:
            suffix = UscanUtils.get_suffix(sigfile_base)
            decompress_cmds = {
                '.gz': '/bin/gunzip',
                '.xz': '/usr/bin/unxz',
                '.bz2': '/bin/bunzip2',
                '.lzma': '/usr/bin/unlzma',
                '.zst': '/usr/bin/unzstd'
            }
            decompress_cmd = decompress_cmds.get(suffix)
            if decompress_cmd and shutil.which(decompress_cmd):
                subprocess.run([decompress_cmd, "--keep", os.path.join(self.config['destdir'], sigfile_base)])
                sigfile_base = re.sub(rf"{suffix}$", "", sigfile_base)
            else:
                UscanOutput.uscan_warn(f"Install required tool to decompress {suffix} files.")
                return 1

        # Signature verification
        pgpsig_url = None
        if self.pgpmode in ['default', 'auto'] and self.shared.get('signature') == 1:
            UscanOutput.uscan_verbose("Checking for common OpenPGP signatures.")
            for suffix in ['asc', 'gpg', 'pgp', 'sig', 'sign']:
                sig_url = f"{self.upstream_url}.{suffix}"
                if self.downloader.user_agent.head(sig_url).ok:
                    if self.pgpmode == 'default':
                        UscanOutput.uscan_warn(
                            f"Possible signature found at: {sig_url}\nAdd opts=pgpsigurlmangle=s/\\$/.{suffix}/ "
                            "or opts=pgpmode=auto in debian/watch for more details."
                        )
                        self.pgpmode = 'none'
                    else:
                        self.pgpmode = 'mangle'
                        self.pgpsigurlmangle = [f"s/$/.'{suffix}'/"]
                    break
            UscanOutput.uscan_verbose("Finished checking for signature files.")
            self.signature_available = 0
        if self.pgpmode == 'mangle':
            pgpsig_url = self.upstream_url
            if UscanUtils.mangle(self.watchfile, self.line, 'pgpsigurlmangle:', self.pgpsigurlmangle, pgpsig_url):
                return 1
            suffix_sig = re.search(r"\.[a-zA-Z]+$", pgpsig_url).group(0)[1:] if re.search(r"\.[a-zA-Z]+$",
                                                                                          pgpsig_url) else "pgp"
            UscanOutput.uscan_debug(f"Adding {suffix_sig} suffix based on {pgpsig_url}.")
            sigfile = f"{sigfile_base}.{suffix_sig}"

            if self.shared.get('signature') == 1:
                UscanOutput.uscan_verbose(f"Downloading signature from {pgpsig_url} as {sigfile}")
                self.signature_available = self.downloader.download(
                    pgpsig_url, os.path.join(self.config['destdir'], sigfile), self,
                    self.parse_result.get('base'), self.pkg_dir, self.pkg, self.mode
                )
            else:
                self.signature_available = 1 if os.path.exists(os.path.join(self.config['destdir'], sigfile)) else 0
            self.sigfile = os.path.join(self.config['destdir'], sigfile)

    def mkorigtargz(self):
        """Call mk_origtargz to build source tarball."""
        UscanOutput.uscan_debug("line: mkorigtargz()")
        if not self.must_download:
            return 0

        path = os.path.join(self.config['destdir'], self.newfile_base)
        target = self.newfile_base

        if self.symlink not in ["no", "0"]:
            UscanOutput.uscan_verbose("Preparing mk-origtargz options.")
            args = ["--package", self.pkg, "--version", self.shared.get("common_mangled_newversion", "")]
            if self.repacksuffix:
                args += ["--repack-suffix", self.repacksuffix]
            if self.symlink == "rename":
                args.append("--rename")
            elif self.symlink == "copy":
                args.append("--copy")
            if self.signature_available != 0:
                args += ["--signature", str(self.signature_available)]
                sigfile_path = os.path.join(self.config['destdir'], self.search_result.get("sigfile", ""))
                args += ["--signature-file", sigfile_path]
            if self.repack:
                args.append("--repack")
            if self.force_repack:
                args.append("--force-repack")
            if self.component:
                args += ["--component", self.component]
            compression = UscanUtils.get_compression(self.compression or "xz")
            args += ["--compression", compression]
            args += ["--directory", self.config['destdir']]
            if self.config.get("exclusion") and Path("debian/copyright").exists():
                args += ["--copyright-file", "debian/copyright"]
            elif self.config.get("exclusion") and self.config.get("copyright_file"):
                args += ["--copyright-file", self.config['copyright_file']]
            if self.unzipopt:
                args += ["--unzipopt", self.unzipopt]
            args.append(path)

            UscanOutput.uscan_verbose("Running mk-origtargz with options: " + " ".join(args))
            result = subprocess.run(["mk-origtargz"] + args, capture_output=True, text=True)
            if result.returncode != 0:
                UscanOutput.uscan_die("mk-origtargz failed")

            path = Path(result.stdout.strip())
            target = path.name
            version_match = re.search(r'[^_]+_(.+)\.orig(?:-.+)?\.tar\.(?:gz|bz2|lzma|xz)$', target)
            if version_match:
                self.shared["common_mangled_newversion"] = version_match.group(1)
            UscanOutput.uscan_verbose(f"New orig.tar.* tarball version (after mk-origtargz): "
                                      f"{self.shared.get('common_mangled_newversion')}")

        self.shared.setdefault("origtars", []).append(target)

        if self.config.get("log"):
            uscanlog_path = Path(self.config['destdir'], f"{self.pkg}_{self.shared['common_mangled_newversion']}.uscan.log")
            uscanlog_old = uscanlog_path.with_suffix(".uscan.log.old")
            if uscanlog_old.exists():
                uscanlog_old.unlink()
                UscanOutput.uscan_warn(f"Removed old backup log: {uscanlog_old}")

            if uscanlog_path.exists():
                uscanlog_path.rename(uscanlog_old)
                UscanOutput.uscan_warn(f"Moved old uscan log to: {uscanlog_old}")

            with open(uscanlog_path, 'a') as uscanlog:
                uscanlog.write("# uscan log\n")
                if self.symlink != "rename":
                    umd5sum = hashlib.md5()
                    omd5sum = hashlib.md5()

                    with open(path, 'rb') as uf, open(os.path.join(self.config['destdir'], target), 'rb') as of:
                        umd5sum.update(uf.read())
                        omd5sum.update(of.read())
                    umd5hex = umd5sum.hexdigest()
                    omd5hex = omd5sum.hexdigest()

                    if umd5hex == omd5hex:
                        uscanlog.write(f"# == {self.newfile_base}\t-->\t{target}\t(same)\n")
                    else:
                        uscanlog.write(f"# !! {self.newfile_base}\t-->\t{target}\t(changed)\n")
                    uscanlog.write(f"{umd5hex}  {self.newfile_base}\n")
                    uscanlog.write(f"{omd5hex}  {target}\n")

    def clean(self):
        """Clean temporary files."""
        UscanOutput.uscan_debug("Running clean()")
        self._do("clean")


    def _do(self, sub):
        """Internal method to dynamically call the correct function based on mode."""
        mode = self.mode.replace("git-dumb", "git")
        method_name = f"{mode}_{sub}"
        try:
            method = getattr(self, method_name)
            return method()
        except AttributeError:
            UscanOutput.uscan_warn(
                f"Unknown '{mode}' mode set in {self.watchfile}"
            )
            self.status = 1
            return None, None