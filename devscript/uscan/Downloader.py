import os
import sys
import subprocess
import shutil
from urllib.parse import urlparse
import tempfile
from pathlib import Path

import CatchRedirections
import UscanOutput
import UscanUtils

class Downloader:
    haveSSL = True

    def __init__(self):
        self.git_upstream = None
        self.agent = f"Debian uscan {self.get_uscan_version()}"
        self.timeout = None
        self.pasv = "default"
        self.destdir = None
        self.gitrepo_state = 0  # 0: no repo, 1: shallow clone, 2: full clone
        self.git_export_all = False
        self.headers = {}
        self.ssl = self.check_ssl_support()
        self.user_agent = None

    def get_uscan_version(self):
        """Retrieves uscan version, mockup for now"""
        return "1.0"  # Mock version or replace this with actual version retrieval

    def check_ssl_support(self):
        """Check if SSL is supported"""
        try:
            import ssl
            return True
        except ImportError:
            return False

    def set_pasv_mode(self, nv):
        """Set or unset FTP passive mode"""
        if nv:
            UscanOutput.uscan_verbose(f"Set passive mode: {self.pasv}")
            os.environ['FTP_PASSIVE'] = self.pasv
        elif 'FTP_PASSIVE' in os.environ:
            UscanOutput.uscan_verbose("Unset passive mode")
            del os.environ['FTP_PASSIVE']

    def get_user_agent(self):
        """Creates or retrieves the user agent object."""
        if not self.user_agent:
            user_agent = CatchRedirections(env_proxy=True)
            user_agent.set_timeout(self.timeout)
            user_agent.set_agent(self.agent)

            # Custom handler for removing Referer for sourceforge.net
            user_agent.add_handler(
                "request_prepare",
                lambda request: request.remove_header("Referer"),
                hostname="sourceforge.net"
            )
            self.user_agent = user_agent
        return self.user_agent