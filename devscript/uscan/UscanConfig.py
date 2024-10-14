import sys
import os
from devscript.DevConfig import DevConfig
import UscanOutput


class UscanConfig(DevConfig):
    CURRENT_WATCHFILE_VERSION = 4

    @property
    def default_user_agent(self):
        uscan_version = getattr(self, 'uscan_version', '')
        return f"Debian uscan {uscan_version}" if uscan_version else "Debian uscan"

    def __init__(self):
        super().__init__()
        self.bare = None
        self.check_dirname_level = None
        self.check_dirname_regex = None
        self.compression = None
        self.copyright_file = None
        self.destdir = None
        self.download = None
        self.download_current_version = None
        self.download_debversion = None
        self.download_version = None
        self.exclusion = None
        self.log = None
        self.orig = None
        self.package = None
        self.pasv = None
        self.http_header = {}
        self.repack = None
        self.safe = None
        self.signature = None
        self.symlink = None
        self.timeout = None
        self.user_agent = None
        self.uversion = None
        self.vcs_export_uncompressed = None
        self.watchfile = None

    @staticmethod
    def keys():
        return [
            ['check-dirname-level=s', 'DEVSCRIPTS_CHECK_DIRNAME_LEVEL', r'^[012]$', 1],
            ['check-dirname-regex=s', 'DEVSCRIPTS_CHECK_DIRNAME_REGEX', None, 'PACKAGE(-.+)?'],
            ['dehs!', 'USCAN_DEHS_OUTPUT', lambda self, val: setattr(self, 'dehs', val)],
            ['destdir=s', 'USCAN_DESTDIR', lambda self, val: (setattr(self, 'destdir', val) if os.path.isdir(val) else (0, f"The directory to store downloaded files: {val}"))],
            ['exclusion!', 'USCAN_EXCLUSION', 'bool', 1],
            ['timeout=i', 'USCAN_TIMEOUT', r'^\d+$', 20],
            ['user-agent|useragent=s', 'USCAN_USER_AGENT', r'\w+', lambda self: self.default_user_agent],
            ['repack', 'USCAN_REPACK', 'bool'],
            ['bare', None, 'bool', 0],
            ['compression=s'],
            ['copyright-file=s'],
            ['download-current-version', None, 'bool'],
            ['download-version=s'],
            ['download-debversion|dversion=s'],
            ['log', None, 'bool'],
            ['package=s'],
            ['uversion|upstream-version=s'],
            ['vcs-export-uncompressed', 'USCAN_VCS_EXPORT_UNCOMPRESSED', 'bool'],
            ['watchfile=s'],
            ['http-header=s', 'USCAN_HTTP_HEADER', None, lambda self: {}],
            [None, 'USCAN_DOWNLOAD', lambda self, val: (setattr(self, 'download', 0) if val.lower() == 'no' else 1)],
            ['download|d+', None, lambda self, val: (setattr(self, 'download', int(val)) if val.isdigit() and 0 <= int(val) <= 3 else (0, "Wrong number of -d"))],
            ['force-download', None, lambda self: setattr(self, 'download', 2)],
            ['no-download', None, lambda self: setattr(self, 'download', 0)],
            ['overwrite-download', None, lambda self: setattr(self, 'download', 3)],
            ['pasv|passive', 'USCAN_PASV', lambda self, val: setattr(self, 'pasv', {'yes': 1, '1': 1, 'no': 0, '0': 0}[val])],
            ['safe|report', 'USCAN_SAFE', 'bool', 0],
            ['report-status', None, lambda self: setattr(self, 'safe', 1)],
            ['copy', None, lambda self: setattr(self, 'symlink', 'copy')],
            ['rename', None, lambda self, val: setattr(self, 'symlink', 'rename' if val else '')],
            ['symlink!', 'USCAN_SYMLINK', lambda self, val: setattr(self, 'symlink', val if val in ['yes', 'no', 'symlink', 'rename'] else 'no')],
            ['signature!', None, 'bool', 1],
            ['skipsignature|skip-signature', None, lambda self: setattr(self, 'signature', -1)],
            ['debug', None, lambda self: setattr(self, 'verbose', 2)],
            ['extra-debug', None, lambda self: setattr(self, 'verbose', 3)],
            ['no-verbose', None, lambda self: setattr(self, 'verbose', 0)],
            ['verbose|v+', 'USCAN_VERBOSE', lambda self, val: setattr(self, 'verbose', 1 if val.lower() == 'yes' else int(val) if val.isdigit() else 0)],
            ['version', None, lambda self, val: (self.version(), exit(0)) if val else None],
        ]

    @staticmethod
    def rules():
        return [
            lambda self: (0, "The --package option requires --watchfile") if self.package and not self.watchfile else 1,
            lambda self: (self.signature(-1), 1)[1] if self.download == 0 else 1,
            lambda self: (0, "Can't have directory arguments with --watchfile") if self.watchfile and len(
                sys.argv) > 1 else 1
        ]

    def usage(self):
        print(f"""
    Usage: {self.progname} [options] [dir ...]
      Process watch files in all .../debian/ subdirs of those listed (or the
      current directory if none listed) to check for upstream releases.
    Options:
        --no-conf, --noconf
                       Don’t read devscripts config files;
                       must be the first option given
        --no-verbose   Don’t report verbose information.
        --verbose, -v  Report verbose information.
        --debug, -vv   Report verbose information including the downloaded
                       web pages as processed to STDERR for debugging.
        --extra-debug, -vvv  Report also remote content during "search" step
        --dehs         Send DEHS style output (XML-type) to STDOUT, while
                       send all other uscan output to STDERR.
        --no-dehs      Use only traditional uscan output format (default)
        --download, -d
                       Download the new upstream release (default)
        --force-download, -dd
                       Download the new upstream release, even if up-to-date
                       (may not overwrite the local file)
        --overwrite-download, -ddd
                       Download the new upstream release, even if up-to-date
                       (may overwrite the local file)
        --no-download, --nodownload
                       Don’t download and report information.
                       Previously downloaded tarballs may be used.
                       Change default to --skip-signature.
        --signature    Download signature and verify (default)
        --no-signature Don’t download signature but verify if already downloaded.
        --skip-signature
                       Don’t bother download signature nor verify it.
        --safe, --report
                       avoid running unsafe scripts by skipping both the repacking
                       of the downloaded package and the updating of the new
                       source tree.  Change default to --no-download and
                       --skip-signature.
        --report-status (= --safe --verbose)
        --download-version VERSION
                       Specify the version which the upstream release must
                       match in order to be considered, rather than using the
                       release with the highest version
        --download-debversion VERSION
                       Specify the Debian package version to download the
                       corresponding upstream release version. The
                       dversionmangle and uversionmangle rules are
                       considered.
        --download-current-version
                       Download the currently packaged version
        --check-dirname-level N
                       Check parent directory name?
                       N=0   never check parent directory name
                       N=1   only when {self.progname} changes directory (default)
                       N=2   always check parent directory name
        --check-dirname-regex REGEX
                       What constitutes a matching directory name; REGEX is
                       a Perl regular expression; the string ‘PACKAGE’ will
                       be replaced by the package name; see manpage for details
                       (default: 'PACKAGE(-.+)?')
        --destdir      Path of directory to which to download.
        --package PACKAGE
                       Specify the package name rather than examining
                       debian/changelog; must use --upstream-version and
                       --watchfile with this option, no directory traversing
                       will be performed, no actions (even downloading) will be
                       carried out
        --upstream-version VERSION
                       Specify the current upstream version in use rather than
                       parsing debian/changelog to determine this
        --watchfile FILE
                       Specify the watch file rather than using debian/watch;
                       no directory traversing will be done in this case
        --bare         Disable all site specific special case codes to perform URL
                       redirections and page content alterations.
        --no-exclusion Disable automatic exclusion of files mentioned in
                       debian/copyright field Files-Excluded and Files-Excluded-*
        --pasv         Use PASV mode for FTP connections
        --no-pasv      Don’t use PASV mode for FTP connections (default)
        --no-symlink   Don’t rename nor repack upstream tarball
        --timeout N    Specifies how much time, in seconds, we give remote
                       servers to respond (default 20 seconds)
        --user-agent, --useragent
                       Override the default user agent string
        --log          Record md5sum changes of repackaging
        --help         Show this message
        --version      Show version information

    Options passed on to mk-origtargz:
        --symlink      Create a correctly named symlink to downloaded file (default)
        --rename       Rename instead of symlinking
        --copy         Copy instead of symlinking
        --repack       Repack downloaded archives to change compression
        --compression [ gzip | bzip2 | lzma | xz ]
                       When the upstream sources are repacked, use compression COMP
                       for the resulting tarball (default: gzip)
        --copyright-file FILE
                       Remove files matching the patterns found in FILE

    Default settings modified by devscripts configuration files:
    {self.modified_conf_msg}
    """)

    def version(self):
        print(f"""This is {UscanOutput.progname}, version {getattr(self, 'uscan_version', 'unknown')}
    This program is part of Debian devscripts.
    """)

