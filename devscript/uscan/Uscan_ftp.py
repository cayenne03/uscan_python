import re
import requests
from UscanOutput import UscanOutput
from UscanUtils import UscanUtils
from Uscan_xtp import Uscan_xtp
from devscript import Versort

class Uscan_ftp:
    def __init__(self, parse_result, downloader, search_result, uversionmangle, watchfile, line, shared=None, versionmode='ignore'):
        """
        Initialize the Uscan_ftp class with attributes similar to the Perl module.
        """
        self.parse_result = parse_result  # Information parsed from the watchfile (base URL, file pattern)
        self.downloader = downloader  # The downloader object managing user agent and download tasks
        self.search_result = search_result  # A dictionary containing the results of the search (new file, new version)
        self.uversionmangle = uversionmangle  # List of patterns to mangle versions
        self.watchfile = watchfile  # The watchfile path
        self.line = line  # The current line being processed
        self.shared = shared or {}  # Shared data such as download_version
        self.versionmode = versionmode  # Version mode (e.g., 'ignore')

    def ftp_search(self):
        """
        Search the FTP site for matching files and extract version information.
        """
        UscanOutput.uscan_verbose(f"Requesting URL:\n   {self.parse_result['base']}")

        # Perform the GET request to the FTP site
        response = requests.get(self.parse_result['base'])
        if response.status_code != 200:
            UscanOutput.uscan_warn(
                f"In watch file {self.watchfile}, reading FTP directory\n  {self.parse_result['base']} failed: {response.status_code}"
            )
            return None

        content = response.text
        UscanOutput.uscan_extra_debug(f"received content:\n{content}\n[End of received content] by FTP")

        UscanOutput.uscan_verbose(f"matching pattern {self.parse_result['pattern']}")
        files = []

        # Check if the listing is HTMLized
        if re.search(r'<\s*a\s+[^>]*href', content, re.IGNORECASE):
            UscanOutput.uscan_verbose("HTMLized FTP listing by the HTTP proxy")
            matches = re.findall(r'<\s*a\s+[^>]*href\s*=\s*\"([^\"]*)\"', content)
            for match in matches:
                file = UscanUtils.fix_href(match)
                mangled_version = ".".join(re.match(self.parse_result['pattern'], file).groups())
                if UscanUtils.mangle(self.watchfile, self.line, 'uversionmangle:', self.uversionmangle, mangled_version):
                    return None
                priority = f"{mangled_version}-{UscanUtils.get_priority(file)}"
                files.append([priority, mangled_version, file, ''])

        else:
            UscanOutput.uscan_verbose("Standard FTP listing.")
            for line in content.splitlines():
                line = re.sub(r'^\s*d.*$', '', line)  # Skip directory listings
                line = re.sub(r'\s+->\s+\S+$', '', line)  # Remove symbolic links
                match = re.search(r'(\S+)$', line)
                if match:
                    file = match.group(1)
                    if re.match(self.parse_result['pattern'], file):
                        mangled_version = ".".join(re.match(self.parse_result['pattern'], file).groups())
                        if UscanUtils.mangle(self.watchfile, self.line, 'uversionmangle:', self.uversionmangle, mangled_version):
                            return None
                        priority = f"{mangled_version}-{UscanUtils.get_priority(file)}"
                        files.append([priority, mangled_version, file, ''])

        if not files:
            UscanOutput.uscan_warn(f"In {self.watchfile} no matching files for watch line\n  {self.line}")
            return None

        # Sort the files using version sorting
        files = Versort.versort(files)

        # Log the sorted files
        msg = "Found the following matching files on the web page (newest first):\n"
        for file in files:
            msg += f"   {file[2]} ({file[1]}) index={file[0]} {file[3]}\n"
        UscanOutput.uscan_verbose(msg)

        # Extract the newest file and version
        if 'download_version' in self.shared and self.shared['download_version']:
            vfiles = [f for f in files if f[3]]
            if vfiles:
                newfile, newversion = vfiles[0][2], vfiles[0][1]
            else:
                UscanOutput.uscan_warn(
                    f"In {self.watchfile} no matching files for version {self.shared['download_version']} in watch line\n  {self.line}"
                )
                return None
        else:
            newfile, newversion = files[0][2], files[0][1]

        self.search_result['newfile'], self.search_result['newversion'] = newfile, newversion
        return newversion, newfile

    def ftp_upstream_url(self):
        """
        Construct the URL to download the new file from the FTP server.
        """
        return f"{self.parse_result['base']}{self.search_result['newfile']}"

    def ftp_newfile_base(self):
        """
        Generate the base name for the new file using Uscan_xtp.
        """
        xtp = Uscan_xtp(
            upstream_url=self.parse_result['base'],
            search_result=self.search_result,
            filenamemangle=self.parse_result.get('filenamemangle', []),
            versionless=self.parse_result.get('versionless', False),
            watchfile=self.watchfile,
            line=self.line,
            mode='ftp'
        )
        return xtp._xtp_newfile_base()

    def ftp_newdir(self, line, site, dir, pattern, dirversionmangle, watchfile, lineptr, download_version):
        """
        Search for new directories matching the pattern on the FTP site.
        """
        downloader = line.downloader
        newdir = None
        download_version_short1, download_version_short2, download_version_short3 = Uscan_xtp.partial_version(download_version)

        # Request the content of the directory
        base = f"{site}{dir}"
        response = requests.get(base)
        if response.status_code != 200:
            UscanOutput.uscan_warn(f"In watch file {watchfile}, reading webpage\n  {base} failed: {response.status_code}")
            return ''

        content = response.text
        UscanOutput.uscan_extra_debug(f"received content:\n{content}\n[End of received content] by FTP")
        dirs = []

        # Handle HTMLized listings
        if re.search(r'<\s*a\s+[^>]*href', content, re.IGNORECASE):
            UscanOutput.uscan_verbose("HTMLized FTP listing by the HTTP proxy")
            matches = re.findall(r'<\s*a\s+[^>]*href\s*=\s*\"([^\"]*)\"', content)
            for match in matches:
                directory = UscanUtils.fix_href(match)
                mangled_version = ".".join(re.match(pattern, directory).groups())
                if UscanUtils.mangle(watchfile, lineptr, 'dirversionmangle:', dirversionmangle, mangled_version):
                    return None
                dirs.append([mangled_version, directory])

        # Handle standard listings
        else:
            UscanOutput.uscan_verbose("Standard FTP listing.")
            for line in content.splitlines():
                match = re.search(r'(\S+)$', line)
                if match:
                    directory = match.group(1)
                    if re.match(pattern, directory):
                        mangled_version = ".".join(re.match(pattern, directory).groups())
                        if UscanUtils.mangle(watchfile, lineptr, 'dirversionmangle:', dirversionmangle, mangled_version):
                            return None
                        dirs.append([mangled_version, directory])

        # extract ones which have a match
        vdirs = [d for d in dirs if d[2]]
        if vdirs:
            vdirs = Versort.upstream_versort(vdirs)
            newdir = vdirs[0][1]

        # Sort all dirs and log results
        if dirs:
            dirs = Versort.upstream_versort(dirs)
            msg = "Found the following matching FTP directories (newest first):\n"
            for dir_info in dirs:
                msg += f"   {dir_info[1]} ({dir_info[0]}) {dir_info[2]}\n"
            UscanOutput.uscan_verbose(msg)
            newdir = newdir or dirs[0][1]  # If no newdir was found earlier, use the first sorted directory
        else:
            UscanOutput.uscan_warn(f"In {watchfile} no matching dirs for pattern\n  {base}{pattern}")
            newdir = ''

        return newdir

    def ftp_clean(self):
        """
        No cleaning needed for FTP.
        """
        return 0
