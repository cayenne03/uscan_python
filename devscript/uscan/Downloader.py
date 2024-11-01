import os
import requests
import shutil
import subprocess
import re
import tempfile
from pathlib import Path
from CatchRedirections import CatchRedirections
import UscanOutput
import UscanUtils


class Downloader:
    def __init__(self, git_upstream=False, agent=None, timeout=None, pasv='default', destdir=None):
        self.git_upstream = git_upstream
        self.agent = agent or "Debian uscan"
        self.timeout = timeout
        self.pasv = pasv
        self.destdir = destdir
        self.gitrepo_state = 0  # 0: no repo, 1: shallow clone, 2: full clone
        self.git_export_all = False
        self.ssl = self._check_ssl()
        self.headers = {}

        self.user_agent = self._create_user_agent()

        # Set FTP passive mode if specified
        if self.pasv != 'default':
            UscanOutput.uscan_verbose(f"Set passive mode: {self.pasv}")
            os.environ['FTP_PASSIVE'] = self.pasv

    def _create_user_agent(self):
        user_agent = CatchRedirections()
        user_agent.headers.update({'User-Agent': self.agent})
        if self.timeout:
            user_agent.timeout = self.timeout
        # Strip Referer for Sourceforge to avoid refresh redirects
        user_agent.hooks['request'] = [self._strip_referer]
        return user_agent

    def _strip_referer(self, request, **kwargs):
        """Strip Referer header specifically for Sourceforge requests."""
        if 'sourceforge.net' in request.url:
            request.headers.pop('Referer', None)
        return request

    def _check_ssl(self):
        """Check for SSL availability."""
        try:
            requests.get('https://example.com')
            return True
        except requests.exceptions.SSLError:
            UscanOutput.uscan_warn("SSL support is required for HTTPS URLs but is not available")
            return False

    def download(self, url, fname, optref, base, pkg_dir, pkg, mode=None, gitrepo_dir=None):
        """Download files from HTTP, FTP, or Git sources."""
        mode = mode or optref.mode
        if mode == 'http':
            return self._download_http(url, fname, base)
        elif mode == 'ftp':
            return self._download_ftp(url, fname)
        elif mode == 'git':
            return self._download_git(url, fname, optref, base, pkg_dir, pkg, gitrepo_dir)
        else:
            UscanOutput.uscan_warn(f"Unsupported download mode: {mode}")
            return False

    def _download_http(self, url, fname, base):
        if url.startswith("https") and not self.ssl:
            UscanOutput.uscan_die(f"{UscanOutput.progname}: SSL support is required for HTTPS URLs")

        UscanOutput.uscan_verbose(f"Requesting URL:\n   {url}")
        headers = {"Accept": "*/*", "Referer": base}

        # Custom headers per site
        for key, value in self.headers.items():
            host_match = key.split('@', 1)
            if len(host_match) == 2 and url.startswith(host_match[0]):
                headers[host_match[1]] = value
                UscanOutput.uscan_verbose(f"Set custom header for {url}: {host_match[1]}")
            elif '@' not in key:
                UscanOutput.uscan_warn(f"Malformed HTTP header: {key}")

        try:
            response = self.user_agent.get(url, headers=headers, stream=True)
            if response.status_code != 200:
                UscanOutput.uscan_warn(f"Downloading\n  {url} failed: {response.status_code} {response.reason}")
                return False

            with open(fname, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        except requests.RequestException as e:
            UscanOutput.uscan_warn(f"Failed to download {url}: {str(e)}")
            return False

    def _download_ftp(self, url, fname):
        UscanOutput.uscan_verbose(f"Requesting URL:\n   {url}")
        try:
            response = self.user_agent.get(url, stream=True)
            if response.status_code != 200:
                UscanOutput.uscan_warn(f"Downloading\n  {url} failed: {response.status_code} {response.reason}")
                return False

            with open(fname, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        except requests.RequestException as e:
            UscanOutput.uscan_warn(f"Failed to download {url}: {str(e)}")
            return False

    def _download_git(self, url, fname, optref, base, pkg_dir, pkg, gitrepo_dir):
        destdir = Path(self.destdir)
        abs_dst = Path(fname).parent.absolute()
        pkg_version = re.search(rf"{pkg}-([\d\w.]+)\.tar", fname).group(1) if re.search(rf"{pkg}-([\d\w.]+)\.tar",
                                                                                        fname) else ""
        suffix = Path(fname).suffix.replace('.', '')

        gitrepo, gitref = url.split(maxsplit=1)
        clean = lambda: shutil.rmtree(gitrepo_dir, ignore_errors=True)

        if self.git_upstream:
            self._handle_git_upstream(abs_dst, pkg, pkg_version, gitref)
        else:
            self._handle_git_download(gitrepo, gitref, base, destdir, gitrepo_dir, abs_dst, pkg, pkg_version)

        if suffix:
            self._compress_tar(abs_dst, pkg, pkg_version, suffix)

        clean()
        return True

    def _handle_git_upstream(self, abs_dst, pkg, version, gitref):
        if self.git_export_all:
            self._override_git_attributes()

        self._git_archive(gitref, abs_dst, pkg, version)
        if self.git_export_all:
            self._restore_git_attributes()

    def _handle_git_download(self, gitrepo, gitref, base, destdir, gitrepo_dir, abs_dst, pkg, version):
        if self.gitrepo_state == 0:
            if self.gitmode == 'shallow':
                self._shallow_git_clone(gitref, base, destdir, gitrepo_dir)
                self.gitrepo_state = 1
            else:
                self._full_git_clone(base, destdir, gitrepo_dir)
                self.gitrepo_state = 2

        if self.git_export_all:
            self._override_git_attributes()

        self._git_archive(gitref, abs_dst, pkg, version, gitrepo_dir)
        if self.git_export_all:
            self._restore_git_attributes()

    def _override_git_attributes(self):
        infodir, attr_file, attr_bkp = self._get_git_paths()
        Path(infodir).mkdir(parents=True, exist_ok=True)
        if attr_file.exists():
            attr_bkp.write_bytes(attr_file.read_bytes())
        with open(attr_file, 'w') as f:
            f.write("* -export-subst\n* -export-ignore\n")

    def _restore_git_attributes(self):
        infodir, attr_file, attr_bkp = self._get_git_paths()
        if attr_bkp.exists():
            attr_file.write_bytes(attr_bkp.read_bytes())
        else:
            attr_file.unlink()

    def _get_git_paths(self):
        infodir = subprocess.run(["git", "rev-parse", "--git-path", "info/"], capture_output=True,
                                 text=True).stdout.strip()
        attr_file = Path(subprocess.run(["git", "rev-parse", "--git-path", "info/attributes"], capture_output=True,
                                        text=True).stdout.strip())
        attr_bkp = Path(f"{attr_file}-uscan")
        return infodir, attr_file, attr_bkp

    def _git_archive(self, gitref, abs_dst, pkg, version, gitrepo_dir=None):
        cmd = [
            'git', "--git-dir={}".format(gitrepo_dir or ""),
            'archive', '--format=tar', f"--prefix={pkg}-{version}/",
            f"--output={abs_dst}/{pkg}-{version}.tar", gitref
        ]
        if subprocess.run(cmd).returncode != 0:
            UscanOutput.uscan_die("git archive failed")

    def _shallow_git_clone(self, tag, base, destdir, gitrepo_dir):
        tag = tag.replace("refs/tags/", "").replace("refs/heads/", "")
        cmd = ['git', 'clone', '--bare', '--depth=1', '-b', tag, base, str(destdir / gitrepo_dir)]
        subprocess.run(cmd, check=True)

    def _full_git_clone(self, base, destdir, gitrepo_dir):
        cmd = ['git', 'clone', '--bare', base, str(destdir / gitrepo_dir)]
        subprocess.run(cmd, check=True)

    def _compress_tar(self, abs_dst, pkg, version, suffix):
        os.chdir(abs_dst)
        tar_file = f"{pkg}-{version}.tar"
        if suffix == 'gz':
            subprocess.run(["gzip", "-n", "-9", tar_file], check=True)
        elif suffix == 'xz':
            subprocess.run(["xz", tar_file], check=True)
        elif suffix == 'bz2':
            subprocess.run(["bzip2", tar_file], check=True)
        elif suffix == 'lzma':
            subprocess.run(["lzma", tar_file], check=True)
        else:
            UscanOutput.uscan_die(f"Unknown suffix file to repack: {suffix}")
        os.chdir(Path.cwd())
