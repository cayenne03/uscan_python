import subprocess
import os
import shutil
from UscanOutput import UscanOutput
from UscanUtils import UscanUtils
from Uscan_vcs import Uscan_vcs


class Uscan_git:
    def __init__(self, versionless, parse_result, search_result, gitrepo_dir, uversionmangle, watchfile, line, mode,
                 downloader, pretty='describe', gitmode='full', date='iso'):
        """
        Initializes the Uscan_git class with attributes related to Git repository handling.

        :param versionless: Boolean indicating if the repository is versionless.
        :param parse_result: Dictionary containing parsed results from the watch file.
        :param search_result: Dictionary containing information about the new file and version.
        :param gitrepo_dir: Directory name for the cloned Git repository.
        :param uversionmangle: List of version mangling rules.
        :param watchfile: Path to the watch file.
        :param line: The current line in the watch file being processed.
        :param mode: The mode of operation ('git' or other).
        :param downloader: Downloader object managing repository states.
        :param pretty: Format for git describe or log.
        :param gitmode: Mode for cloning ('full' or 'shallow').
        :param date: Date format for git log.
        """
        self.versionless = versionless
        self.parse_result = parse_result
        self.search_result = search_result
        self.gitrepo_dir = gitrepo_dir
        self.uversionmangle = uversionmangle
        self.watchfile = watchfile
        self.line = line
        self.mode = mode
        self.downloader = downloader
        self.pretty = pretty
        self.gitmode = gitmode
        self.date = date

    def git_search(self):
        """
        Searches for a new file and version in the Git repository, handling both versionless and tagged modes.

        :return: Tuple containing newversion and newfile, or None if not found.
        """
        newfile, newversion = None, None

        if self.versionless:
            newfile = self.parse_result.get('filepattern')  # e.g., 'HEAD' or 'heads/<branch>'

            if self.pretty == 'describe':
                self.gitmode = 'full'

            # Handle shallow cloning
            if self.gitmode == 'shallow' and self.parse_result.get('filepattern') == 'HEAD':
                clone_command = [
                    'git', 'clone', '--quiet', '--bare', '--depth', '1',
                    self.parse_result.get('base'),
                    os.path.join(self.downloader.destdir, self.gitrepo_dir)
                ]
                UscanOutput.uscan_verbose(f"Cloning repository shallowly: {' '.join(clone_command)}")
                self._execute_command(clone_command)
                self.downloader.gitrepo_state = 1

            elif self.gitmode == 'shallow' and self.parse_result.get('filepattern') != 'HEAD':
                branch = self.parse_result.get('filepattern').replace('heads/', '')
                clone_command = [
                    'git', 'clone', '--quiet', '--bare', '--depth', '1',
                    '-b', branch,
                    self.parse_result.get('base'),
                    os.path.join(self.downloader.destdir, self.gitrepo_dir)
                ]
                UscanOutput.uscan_verbose(
                    f"Cloning repository shallowly with branch '{branch}': {' '.join(clone_command)}")
                self._execute_command(clone_command)
                self.downloader.gitrepo_state = 1

            else:
                # Full clone
                clone_command = [
                    'git', 'clone', '--quiet', '--bare',
                    self.parse_result.get('base'),
                    os.path.join(self.downloader.destdir, self.gitrepo_dir)
                ]
                UscanOutput.uscan_verbose(f"Cloning repository fully: {' '.join(clone_command)}")
                self._execute_command(clone_command)
                self.downloader.gitrepo_state = 2

            # Retrieve version information
            if self.pretty == 'describe':
                describe_command = [
                    'git', f"--git-dir={os.path.join(self.downloader.destdir, self.gitrepo_dir)}",
                    'describe', '--tags'
                ]
                UscanOutput.uscan_verbose(f"Running git describe: {' '.join(describe_command)}")
                newversion = self._execute_command(describe_command).replace('-', '.').strip()

                # Apply version mangling rules
                if UscanUtils.mangle(self.watchfile, self.line, 'uversionmangle:', self.uversionmangle, newversion):
                    return None

            else:
                # Handle 'log' or other pretty formats
                original_tz = os.environ.get('TZ')
                os.environ['TZ'] = 'UTC'
                newfile = self.parse_result.get('filepattern')  # e.g., 'HEAD' or 'heads/<branch>'

                if newfile == 'HEAD':
                    log_command = [
                        'git', f"--git-dir={os.path.join(self.downloader.destdir, self.gitrepo_dir)}",
                        'log', '-1',
                        f"--date=format-local:{self.date}",
                        f"--pretty={self.pretty}"
                    ]
                else:
                    branch = newfile.replace('heads/', '')
                    log_command = [
                        'git', f"--git-dir={os.path.join(self.downloader.destdir, self.gitrepo_dir)}",
                        'log', '-1', '-b', branch,
                        f"--date=format-local:{self.date}",
                        f"--pretty={self.pretty}"
                    ]

                UscanOutput.uscan_verbose(f"Running git log: {' '.join(log_command)}")
                newversion = self._execute_command(log_command)
                os.environ['TZ'] = original_tz
                newversion = newversion.strip()

            return newversion, newfile

        def git_upstream_url(self):
            """
            Constructs the upstream URL for the Git repository, appending the versioned file path if necessary.

            :return: The upstream URL.
            """
            upstream_url = f"{self.parse_result.get('base')} {self.search_result.get('newfile')}"
            return upstream_url

        def git_newfile_base(self):
            """
            Alias for _vcs_newfile_base, generating the base name for the new file from the Git repository.

            :return: The base name for the new file.
            """
            vcs = Uscan_vcs(
                pkg=None,
                search_result=self.search_result,
                config=None,
                compression=None,
                patterns=None,
                uversionmangle=self.uversionmangle,
                watchfile=self.watchfile,
                line=self.line,
                shared=None
            )
            return vcs._vcs_newfile_base()

        def git_clean(self):
            """
            Cleans up the cloned Git repository by removing its directory if certain conditions are met.

            :return: Always returns 0.
            """
            # Assuming verbosity is managed globally or passed as an argument; here, using UscanOutput
            verbosity = UscanOutput.get_verbose()

            if (self.downloader.gitrepo_state > 0 and
                    verbosity < 2 and
                    not self.downloader.git_upstream):
                repo_path = os.path.join(self.downloader.destdir, self.gitrepo_dir)
                UscanOutput.uscan_verbose(f"Removing git repo ({repo_path})")
                try:
                    shutil.rmtree(repo_path)
                    self.downloader.gitrepo_state = 0
                except Exception as e:
                    UscanOutput.uscan_warn(f"Errors during git repo clean: {e}")
            else:
                repo_path = os.path.join(self.downloader.destdir, self.gitrepo_dir)
                UscanOutput.uscan_debug(f"Keep git repo ({repo_path})")

            return 0

    # Helper method to execute commands
    def _execute_command(self, command):
        """
        Executes a shell command and returns its output.

        :param command: List of command arguments.
        :return: Output of the command as a string.
        """
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            UscanOutput.uscan_die(f"Error running command {' '.join(command)}: {e.stderr.strip()}")
            return None
