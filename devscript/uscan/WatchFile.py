import re
import os
from pathlib import Path
from Downloader import Downloader
import UscanOutput
import UscanConfig
from WatchLine import WatchLine
from Keyring import UscanKeyring
from packaging.version import parse as Version

class WatchFile:
    ANY_VERSION = r'(?:[-_]?[Vv]?(\d[\-+\.:\~\da-zA-Z]*))'
    ARCHIVE_EXT = r'(?i)(?:\.(?:tar\.xz|tar\.bz2|tar\.gz|tar\.zstd?|zip|tgz|tbz|txz))'
    DEB_EXT = r'(?:[\+~](debian|dfsg|ds|deb)(\.)?(\d+)?$)'
    SIGNATURE_EXT = f"{ARCHIVE_EXT}(?:\.(?:asc|pgp|gpg|sig|sign))"

    def __init__(self, config, package, pkg_dir, pkg_version, watchfile):
        self.config = config
        self.package = package
        self.pkg_dir = pkg_dir
        self.pkg_version = pkg_version
        self.watchfile = watchfile
        self.bare = config.bare
        self.download = config.download
        self.downloader = Downloader(
            timeout=config.timeout,
            agent=config.user_agent,
            pasv=config.pasv,
            destdir=config.destdir,
            headers=config.http_header
        )
        self.signature = config.signature
        self.group = []
        self.origcount = 0
        self.origtars = []
        self.status = 0
        self.watch_version = 0
        self.watchlines = []
        self.shared = self.new_shared()
        self.keyring = UscanKeyring()

        self._process_watchfile()

    def new_shared(self):
        """Create shared attributes for lines."""
        return {
            'bare': self.bare,
            'components': [],
            'common_newversion': None,
            'common_mangled_newversion': None,
            'download': self.download,
            'download_version': None,
            'origcount': None,
            'origtars': [],
            'previous_download_available': None,
            'previous_newversion': None,
            'previous_newfile_base': None,
            'previous_sigfile_base': None,
            'signature': self.signature,
            'uscanlog': None,
        }

    def _process_watchfile(self):
        """Read and parse the watchfile, setting up WatchLine objects for each line."""
        UscanOutput.uscan_verbose(f"Processing watch file at: {self.watchfile}")
        try:
            with open(self.watchfile) as file:
                line_number = 0
                for line in file:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if self._is_continuation_line(line, file):
                        continue

                    if self.watch_version == 0:
                        self._set_watch_version(line)

                    if self.watch_version < 3:
                        UscanOutput.uscan_warn(
                            f"{self.watchfile} is an obsolete version {self.watch_version} watch file; "
                            "please upgrade to a higher version (see uscan(1) for details)."
                        )

                    line = self._substitute_placeholders(line)
                    watch_line = WatchLine(
                        shared=self.shared,
                        keyring=self.keyring,
                        config=self.config,
                        downloader=self.downloader,
                        line=line,
                        pkg=self.package,
                        pkg_dir=self.pkg_dir,
                        pkg_version=self.pkg_version,
                        watchfile=self.watchfile,
                        watch_version=self.watch_version
                    )

                    if watch_line.type and re.match(r'^(group|checksum)$', watch_line.type):
                        self.group.append(line_number)
                    self.watchlines.append(watch_line)
                    line_number += 1

        except IOError as e:
            UscanOutput.uscan_warn(f"Could not open {self.watchfile}: {str(e)}")
            self.status = 1

    def _is_continuation_line(self, line, file):
        """Handle lines ending in a backslash for continuation."""
        while line.endswith("\\") and not line.endswith(r"\\"):
            line = line.rstrip("\\").strip()
            next_line = next(file, "").strip()
            if self.watch_version > 3:
                next_line = next_line.lstrip()
            line += " " + next_line
            if not next_line:
                UscanOutput.uscan_warn(f"{self.watchfile} ended with \\; skipping last line")
                self.status = 1
                return True
        return False

    def _set_watch_version(self, line):
        """Identify the version field in the watch file."""
        match = re.match(r"^version\s*=\s*(\d+)(\s|$)", line)
        if match:
            self.watch_version = int(match.group(1))
            if self.watch_version < 2 or self.watch_version > UscanConfig.CURRENT_WATCHFILE_VERSION:
                UscanOutput.uscan_warn(
                    f"{self.watchfile} version number is unrecognized; skipping watch file"
                )
                self.status = 1
        else:
            self.watch_version = 1

    def _substitute_placeholders(self, line):
        """Replace placeholders with corresponding values."""
        line = re.sub(r"@PACKAGE@", self.package, line)
        line = re.sub(r"@ANY_VERSION@", self.ANY_VERSION, line)
        line = re.sub(r"@ARCHIVE_EXT@", self.ARCHIVE_EXT, line)
        line = re.sub(r"@SIGNATURE_EXT@", self.SIGNATURE_EXT, line)
        line = re.sub(r"@DEB_EXT@", self.DEB_EXT, line)
        return line

    def process_lines(self):
        """Process each line or group of lines in the watch file."""
        if self.group:
            return self.process_group()

        for watch_line in self.watchlines:
            result = watch_line.process()
            if result:
                self.status = result
        return self.status

    def process_group(self):
        """Handle grouped watch lines with version comparison and checksum logic."""
        saveDconfig = self.config.download_version
        cur_versions = self.pkg_version.split('+~')
        checksum = 0
        newChecksum = 0

        # Handling checksum in the current version
        if cur_versions and cur_versions[-1].startswith('cs'):
            checksum = int(cur_versions.pop(-1)[2:])

        new_versions = []
        last_debian_mangled_uversions = []
        last_versions = []
        download = 0
        last_shared = self.shared
        last_comp_version = None
        dversion = []
        ck_versions = []

        # Parse config version for component handling
        if self.config.download_version:
            dversion = [v.split('+', 1)[0] for v in self.config.download_version.split('+~') if not v.startswith('cs')]

        for line in self.watchlines:
            if line.type in ['group', 'checksum']:
                last_shared = self.new_shared()
                if line.type == 'group':
                    last_comp_version = cur_versions.pop(0) if cur_versions else None
                line.groupDversion = dversion.pop(0) if line.type == 'group' and dversion else None
            line.shared = last_shared
            line.pkg_version = last_comp_version or 0

        # Check if any download is required and process lines accordingly
        for line in self.watchlines:
            if line.type in ['group', 'checksum']:
                if line.groupDversion:
                    self.config.download_version = line.groupDversion
                elif line.type == 'checksum':
                    self.config.download_version = None

                # Run necessary processes for each line
                if (line.parse() or line.search() or line.get_upstream_url() or
                        line.get_newfile_base() or
                        (line.type == 'group' and line.cmp_versions()) or
                        (line.ctype and line.cmp_versions())):
                    self.status += line.status
                    return self.status

                download = max(download, line.shared.get('download', 0))

        # Sum checksums and update each line's version
        for line in self.watchlines:
            if line.type == 'checksum':
                newChecksum = self.sum(newChecksum, line.search_result.get('newversion', ''))
                ck_versions.append(line.search_result.get('newversion', ''))

        for line in self.watchlines:
            if line.type == 'checksum':
                line.parse_result['mangled_lastversion'] = checksum
                tmp_version = line.search_result['newversion']
                line.search_result['newversion'] = newChecksum

                # Compare versions if line is not a component line
                if not line.ctype:
                    if line.cmp_versions():
                        self.status += line.status
                        return self.status
                    download = max(download, line.shared.get('download', 0))

                line.search_result['newversion'] = tmp_version

                if line.component:
                    UscanOutput.dehs_tags.setdefault('component-upstream-version', []).append(tmp_version)

        # Set the same download value across all lines
        for line in self.watchlines:
            line.shared['download'] = download
            if line.type not in ['group', 'checksum']:
                if (line.parse() or line.search() or line.get_upstream_url() or
                        line.get_newfile_base() or line.cmp_versions()):
                    self.status += line.status
                    return self.status

            # Download files and signatures as needed
            if line.download_file_and_sig():
                self.status += line.status
                return self.status

            if line.mkorigtargz():
                self.status += line.status
                return self.status

            # Track new and last versions for each group
            if line.type == 'group':
                new_versions.append(
                    line.shared.get('common_mangled_newversion') or line.shared.get('common_newversion'))
                last_versions.append(line.parse_result.get('lastversion'))
                last_debian_mangled_uversions.append(line.parse_result.get('mangled_lastversion'))

        # Construct version strings with checksums if applicable
        new_version = '+~'.join(filter(None, new_versions))
        if newChecksum:
            new_version += f"+~cs{newChecksum}"

        if checksum:
            last_versions.append(f"cs{newChecksum}")
            last_debian_mangled_uversions.append(f"cs{checksum}")

        # Update dehs_tags with version information
        UscanOutput.dehs_tags['upstream-version'] = new_version
        UscanOutput.dehs_tags['debian-uversion'] = '+~'.join(filter(None, last_versions))
        UscanOutput.dehs_tags['debian-mangled-uversion'] = '+~'.join(filter(None, last_debian_mangled_uversions))

        # Compare upstream and mangled versions
        mangled_ver = Version(f"1:{UscanOutput.dehs_tags['debian-mangled-uversion']}-0")
        upstream_ver = Version(f"1:{new_version}-0")
        if mangled_ver == upstream_ver:
            UscanOutput.dehs_tags['status'] = "up to date"
        elif mangled_ver > upstream_ver:
            UscanOutput.dehs_tags['status'] = "only older package available"
        else:
            UscanOutput.dehs_tags['status'] = "newer package available"

        # Rename downloaded files if necessary
        for line in self.watchlines:
            if line.destfile:
                path = line.destfile
                ver = line.shared.get('common_mangled_newversion')
                path = path.replace(ver, new_version) if ver else path
                UscanOutput.uscan_warn(f"Renaming {line.destfile} to {path}")
                os.rename(line.destfile, path)

                if UscanOutput.dehs_tags.get("target-path") == line.destfile:
                    UscanOutput.dehs_tags["target-path"] = path
                    UscanOutput.dehs_tags["target"] = UscanOutput.dehs_tags["target"].replace(ver, new_version)
                else:
                    for i, component_path in enumerate(UscanOutput.dehs_tags.get("component-target-path", [])):
                        if component_path == line.destfile:
                            UscanOutput.dehs_tags["component-target-path"][i] = path
                            UscanOutput.dehs_tags["component-target"][i] = UscanOutput.dehs_tags["component-target"][
                                i].replace(ver, new_version)

                if line.signature_available:
                    for ext in ['.asc', '.sig']:
                        sig_path = f"{line.destfile}{ext}"
                        if os.path.exists(sig_path):
                            os.rename(sig_path, f"{path}{ext}")

        # Log checksums if available
        if ck_versions:
            UscanOutput.dehs_tags['decoded-checksum'] = '+~'.join(ck_versions) if UscanOutput.dehs else None
            if not UscanOutput.dehs:
                UscanOutput.uscan_verbose(f'Checksum ref: {"+~".join(ck_versions)}')

        return 0

    def sum(self, *versions):
        """Calculate the sum of version components for checksums."""
        res, str_parts = [], []

        for version in versions:
            parts = [p for p in self.version_split_digits(version) if p != '.']
            for i, part in enumerate(parts):
                str_parts.append('') if len(str_parts) <= i else None
                res.append(0) if len(res) <= i else None
                if part.isdigit():
                    res[i] += int(part)
                else:
                    UscanOutput.uscan_die(f"Checksum supports only digits in versions, {part} is not accepted")

        return '.'.join([f"{r}{str_parts[i] if str_parts[i] else ''}" for i, r in enumerate(res)] + str_parts)

    @staticmethod
    def version_split_digits(version):
        """Split version into components for easy parsing."""
        return re.findall(r'\d+|[^\d]+', version)
