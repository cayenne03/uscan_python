import subprocess
import os
import Uscan_vcs
from UscanUtils import UscanUtils
from UscanOutput import UscanOutput


class Uscan_svn:
    def __init__(self, versionless, parse_result, search_result, uversionmangle, watchfile, line, mode):
        """
        Initializes the Uscan_svn class with attributes related to SVN repository handling.
        :param versionless: Boolean indicating if the repository is versionless.
        :param parse_result: Parsed result from the watch file.
        :param search_result: Information about the new file and version.
        :param uversionmangle: A list of version mangling rules.
        :param watchfile: Path to the watch file.
        :param line: The current line in the watch file being processed.
        :param mode: The mode of operation (e.g., 'svn').
        """
        self.versionless = versionless
        self.parse_result = parse_result
        self.search_result = search_result
        self.uversionmangle = uversionmangle
        self.watchfile = watchfile
        self.line = line
        self.mode = mode

    def svn_search(self):
        """
        Searches for a new file and version in the SVN repository, either in versionless mode or with tags.
        :return: Tuple containing newversion and newfile, or None if not found.
        """
        newfile, newversion = None, None

        # Handle versionless SVN repository
        if self.versionless:
            newfile = self.parse_result.get('base')
            command = ['svn', 'info', '--show-item', 'last-changed-revision', '--no-newline', newfile]
            UscanOutput.uscan_verbose(f"Running command: {' '.join(command)}")

            # Execute SVN info command to get the last changed revision
            try:
                newversion = subprocess.check_output(command, text=True).strip()
                newversion = f"0.0~svn{newversion}"
            except subprocess.CalledProcessError as e:
                UscanOutput.uscan_warn(f"Error running SVN command: {e}")
                return None

            # Apply version mangling rules
            if UscanUtils.mangle(self.watchfile, self.line, 'uversionmangle:', self.uversionmangle, newversion):
                return None

        # Handle SVN mode with tags
        elif self.mode == 'svn':
            command = ['svn', 'list', self.parse_result.get('base')]
            UscanOutput.uscan_verbose(f"Running command: {' '.join(command)}")

            vcs = Uscan_vcs(pkg=None, search_result=self.search_result, config=None, compression=None,
                            patterns=None, uversionmangle=self.uversionmangle, watchfile=self.watchfile, line=self.line, shared=None)
            newversion, newfile = vcs.get_refs(command, r"(.+)", 'subversion')

            if not newversion:
                return None

        return newversion, newfile

    def svn_upstream_url(self):
        """
        Constructs the upstream URL for the SVN repository, appending the versioned file path if necessary.
        :return: The upstream URL.
        """
        upstream_url = self.parse_result.get('base')

        if not self.versionless:
            upstream_url += f"/{self.search_result.get('newfile')}"

        return upstream_url

    def svn_newfile_base(self):
        """
        Alias for _vcs_newfile_base, generating the base name for the new file from the SVN repository.
        """
        vcs = Uscan_vcs(pkg=None, search_result=self.search_result, config=None, compression=None,
                        patterns=None, uversionmangle=self.uversionmangle, watchfile=self.watchfile, line=self.line, shared=None)
        return vcs._vcs_newfile_base()

    def svn_clean(self):
        """
        Placeholder function for cleaning up any temporary SVN data if necessary.
        Currently, this function does nothing.
        """
        pass
