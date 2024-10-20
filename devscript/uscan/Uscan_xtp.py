import re
import os
from urllib.parse import urlparse
from UscanUtils import UscanUtils
from UscanOutput import UscanOutput


class Uscan_xtp:
    def __init__(self, upstream_url, search_result, filenamemangle, versionless, watchfile, line, mode):
        """
        Initializes the Uscan_xtp class with attributes from the Perl module.
        :param upstream_url: The URL of the upstream source.
        :param search_result: Information about the new file and version.
        :param filenamemangle: A list of filenamemangle patterns.
        :param versionless: Boolean indicating if the version is omitted from the filename.
        :param watchfile: Path to the watch file.
        :param line: The current line in the watch file being processed.
        :param mode: The mode of operation (http or ftp).
        """
        self.upstream_url = upstream_url
        self.search_result = search_result
        self.filenamemangle = filenamemangle
        self.versionless = versionless
        self.watchfile = watchfile
        self.line = line
        self.mode = mode

    def _xtp_newfile_base(self):
        """
        Determine the new file base from the upstream URL or search result, applying filenamemangle if needed.
        """
        newfile_base = None
        if self.filenamemangle:
            # HTTP or FTP site with filenamemangle
            if self.versionless:
                newfile_base = self.upstream_url
            else:
                newfile_base = self.search_result.get('newfile', '')
            UscanOutput.uscan_verbose(f"Matching target for filenamemangle: {newfile_base}")
            cmp = newfile_base

            if UscanUtils.mangle(self.watchfile, self.line, 'filenamemangle:', self.filenamemangle, newfile_base):
                self.search_result['status'] = 1
                return None

            # If the URL is provided, extract the filename
            if newfile_base.startswith(('http', 'ftp')):
                newfile_base = os.path.basename(urlparse(newfile_base).path)

            # If the filename remains unchanged, fail
            if cmp == newfile_base:
                UscanOutput.uscan_die(f"filenamemangle failed for {cmp}")

            # Try to extract the version from the filename if it wasn't set earlier
            if not self.search_result.get('newversion'):
                match = re.match(r'^.+?[-_]?(\d[\-+.:~\da-zA-Z]*)(?:\.tar\.(gz|bz2|xz|zst)|\.zip)$', newfile_base,
                                 re.IGNORECASE)
                if match:
                    self.search_result['newversion'] = match.group(1)
                else:
                    UscanOutput.uscan_warn("Fix filenamemangle to produce a filename with the correct version")
                    self.search_result['status'] = 1
                    return None

                UscanOutput.uscan_verbose(
                    f"Newest upstream tarball version from the filenamemangled filename: {self.search_result['newversion']}")
        else:
            # HTTP or FTP site without filenamemangle
            newfile_base = os.path.basename(self.search_result.get('newfile', ''))

            if self.mode == 'http':
                # Remove HTTP header trash (e.g., '?', '#')
                newfile_base = re.sub(r'[\?#].*$', '', newfile_base)

                if not newfile_base:
                    UscanOutput.uscan_warn(
                        "No good upstream filename found after removing trailing ?... and #...\n   Use filenamemangle to fix this.")
                    self.search_result['status'] = 1
                    return None

        return newfile_base

    @staticmethod
    def partial_version(download_version):
        """
        Break down the version into parts (major, major.minor, major.minor.patch).
        """
        d1, d2, d3 = None, None, None
        if download_version:
            UscanOutput.uscan_verbose(f"download version requested: {download_version}")
            match = re.match(r'^([-~+\w]+)(\.[-~+\w]+)?(\.[-~+\w]+)?(\.[-~+\w]+)?$', download_version)
            if match:
                d1 = match.group(1) if match.group(1) else None
                d2 = f"{match.group(1)}{match.group(2)}" if match.group(2) else None
                d3 = f"{match.group(1)}{match.group(2)}{match.group(3)}" if match.group(3) else None
        return d1, d2, d3
