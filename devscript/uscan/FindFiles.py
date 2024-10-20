import os
import subprocess
from packaging.version import Version
import UscanOutput
from devscript.Versort import Versort
from debian.changelog import Changelog


class FindFiles:
    @staticmethod
    def changelog_parse(file_path='debian/changelog'):
        """
        Parses a Debian changelog file and returns the package name and version.
        """
        with open(file_path, 'r') as changelog_file:
            changelog = Changelog(changelog_file)

        # Get the first (most recent) entry
        most_recent_entry = changelog[0]

        package = most_recent_entry.package
        version = most_recent_entry.version

        return {
            "Source": package,
            "Version": version,
        }

    @staticmethod
    def find_watch_files(config):
        opwd = os.getcwd()

        # when --watchfile is used
        if config.watchfile is not None:
            UscanOutput.uscan_verbose(f"Option --watchfile={config.watchfile} used")

            # no directory traversing then, and things are very simple
            if config.package is not None:
                return [('.', config.package, config.uversion, config.watchfile)]
            else:
                # Check for debian/changelog file
                while not os.path.isfile('debian/changelog'):
                    os.chdir('..')
                    if os.getcwd() == '/':
                        UscanOutput.uscan_die(
                            "Are you in the source code tree?\n"
                            "Cannot find readable debian/changelog anywhere!"
                        )

                package, debversion, uversion = FindFiles.scan_changelog(config, opwd, die=True)
                return [(os.getcwd(), package, uversion, config.watchfile)]

        # when --watchfile is not used, scan watch files
        args = config.args if config.args else ['.']
        UscanOutput.uscan_verbose(f"Scan watch files in {args}")

        # Run find command to locate directories with debian subdirectories
        find_command = ['find', '-L'] + args + ['-type', 'd', '(', '-name', '.git', '-prune', '-o', '-name', 'debian',
                                                '-print', ')']
        result = subprocess.run(find_command, stdout=subprocess.PIPE, text=True)
        dirs = result.stdout.splitlines()

        if not dirs:
            UscanOutput.uscan_die("No debian directories found")

        debdirs = []
        origdir = os.getcwd()

        for dir in dirs:
            dir = dir.rstrip('/debian')

            try:
                os.chdir(origdir)
                os.chdir(dir)
            except OSError:
                UscanOutput.uscan_warn(f"Couldn't chdir {dir}, skipping")
                continue

            UscanOutput.uscan_verbose(f"Check debian/watch and debian/changelog in {dir}")

            # Check for debian/watch file
            if os.path.isfile('debian/watch'):
                if not os.path.isfile('debian/changelog'):
                    UscanOutput.uscan_warn(f"Problems reading debian/changelog in {dir}, skipping")
                    continue

                package, debversion, uversion = FindFiles.scan_changelog(config, opwd)
                if not package:
                    continue

                UscanOutput.uscan_verbose(f'package="{package}" version="{uversion}" (no epoch/revision)')
                debdirs.append([debversion, dir, package, uversion])

        if not debdirs:
            UscanOutput.uscan_warn("No watch file found")

        # Handle --upstream-version
        if config.uversion:
            if len(debdirs) == 1:
                debdirs[0][3] = config.uversion
            else:
                UscanOutput.uscan_warn(
                    "Ignoring --upstream-version as more than one debian/watch file found"
                )

        # Sort by version and process
        debdirs = Versort.deb_versort(debdirs)
        results = []
        donepkgs = {}

        for debdir in debdirs:
            dir, package, version = debdir[1:]

            if donepkgs.get(os.path.dirname(dir), {}).get(package):
                UscanOutput.uscan_warn(f"Skipping {dir}/debian/watch as this package has already been found")
                continue

            try:
                os.chdir(origdir)
                os.chdir(dir)
            except OSError:
                UscanOutput.uscan_warn(f"Couldn't chdir {dir}, skipping")
                continue

            UscanOutput.uscan_verbose(f"{dir}/debian/changelog sets package={package} version={version}")
            results.append([dir, package, version, "debian/watch", os.getcwd()])

        os.chdir(origdir)
        return results

    @staticmethod
    def scan_changelog(config, opwd, die=False):
        def error_func(msg):
            if die:
                UscanOutput.uscan_die(msg)
            else:
                UscanOutput.uscan_warn(f"{msg}, skipping")
                return None

        # Parse changelog
        try:
            changelog = FindFiles.changelog_parse()
        except Exception as e:
            return error_func("Problems parsing debian/changelog")

        package = changelog.get('Source')
        if not package:
            return error_func("Problem determining the package name from debian/changelog")

        debversion = changelog.get('Version')
        if not debversion:
            return error_func("Problem determining the version from debian/changelog")

        UscanOutput.uscan_verbose(f'package="{package}" version="{debversion}" (as seen in debian/changelog)')

        if config.check_dirname_level == 2 or (config.check_dirname_level == 1 and os.getcwd() != opwd):
            re_pattern = config.check_dirname_regex.replace("PACKAGE", package)
            good_dirname = os.getcwd().startswith(re_pattern) if "/" in re_pattern else os.path.basename(
                os.getcwd()).startswith(re_pattern)

            if not good_dirname:
                return error_func(
                    f"The directory name {os.path.basename(os.getcwd())} doesn't match the requirement of "
                    f"--check-dirname-level={config.check_dirname_level} --check-dirname-regex={re_pattern}. "
                    "Set --check-dirname-level=0 to disable this sanity check feature."
                )

        # Get upstream version
        if config.uversion:
            uversion = config.uversion
        else:
            uversion = debversion.split('-')[0].split(':')[-1]

        return package, debversion, uversion
