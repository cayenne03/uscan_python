import re
import subprocess
import os
from UscanUtils import UscanUtils
from UscanOutput import UscanOutput
from devscript import Versort


class Uscan_vcs:
    def __init__(self, pkg, search_result, config, compression, patterns, uversionmangle, watchfile, line, shared):
        """
        Initializes the Uscan_vcs class with attributes from the Perl module.
        :param pkg: The package name.
        :param search_result: Contains information about the version being searched for.
        :param config: Configuration settings for uscan.
        :param compression: The type of compression being used.
        :param patterns: A list of regex patterns for finding version references.
        :param uversionmangle: A list of version mangling rules.
        :param watchfile: The path to the watch file.
        :param line: The current line in the watch file being processed.
        :param shared: Shared state such as download_version.
        """
        self.pkg = pkg
        self.search_result = search_result
        self.config = config
        self.compression = compression
        self.patterns = patterns
        self.uversionmangle = uversionmangle
        self.watchfile = watchfile
        self.line = line
        self.shared = shared

    def _vcs_newfile_base(self):
        """
        Generate the base name for the new file from the VCS repository.
        If compression is not deferred, append the compression suffix.
        """
        newfile_base = f"{self.pkg}-{self.search_result['newversion']}.tar"
        if not self.config.get('vcs_export_uncompressed'):
            newfile_base += f'.{UscanUtils.get_suffix(self.compression)}'
        return newfile_base

    def get_refs(self, command, ref_pattern, package):
        """
        Execute a VCS command to find references (e.g., Git tags) that match a given pattern.
        Filter the references based on version patterns and return the matching version and reference.

        :param command: The VCS command to execute.
        :param ref_pattern: A regex pattern to match references (e.g., tags).
        :param package: The package that needs to be checked.
        :return: Tuple containing the new version and new file reference, or None if no matching refs are found.
        """
        UscanOutput.uscan_verbose(f"Execute: {' '.join(command)}")

        # Execute the command and capture the output
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, text=True)
            output_lines = result.stdout.splitlines()
        except subprocess.CalledProcessError:
            UscanOutput.uscan_die(f"{os.path.basename(__file__)}: you must have the {package} package installed")
            return None

        refs = []

        # Process each line of the command's output
        for line in output_lines:
            UscanOutput.uscan_debug(line)
            match = re.match(ref_pattern, line)
            if match:
                ref = match.group(1)
                for pattern in self.patterns:
                    version = '.'.join([m for m in re.match(pattern, ref).groups() if m])

                    # Apply version mangling rules
                    if UscanUtils.mangle(self.watchfile, self.line, 'uversionmangle:', self.uversionmangle, version):
                        return None

                    refs.append((version, ref))

        if refs:
            # Sort references using upstream_versort
            refs = Versort.upstream_versort(refs)
            ref_list_str = "\n".join([f"     {r[1]} ({r[0]})" for r in refs])
            UscanOutput.uscan_verbose(f"Found the following matching refs:\n{ref_list_str}")

            # Handle the shared download_version
            if self.shared.get('download_version') and self.search_result['versionmode'] != 'ignore':
                vrefs = [r for r in refs if r[0] == self.shared['download_version']]
                if vrefs:
                    newversion, newfile = vrefs[0]
                else:
                    UscanOutput.uscan_warn(f"{os.path.basename(__file__)} warning: In {self.watchfile} no matching "
                                           f"refs for version {self.shared['download_version']} in watch line\n  {self.line}")
                    return None
            else:
                newversion, newfile = refs[0]
        else:
            UscanOutput.uscan_warn(f"{os.path.basename(__file__)} warning: In {self.watchfile},\n"
                                   f" no matching refs for watch line\n {self.line}")
            return None

        return newversion, newfile
