import os
import shutil
import subprocess
import tempfile
import re
from pathlib import Path
import UscanOutput

class UscanKeyring:
    def __init__(self):
        self.keyring = None
        self.gpghome = None

        # Check if gpgv and gpg are available
        self.gpgv = self.find_executable(['gpgv2', 'gpgv'])
        self.gpg = self.find_executable(['gpg2', 'gpg'])

        if not self.gpgv:
            UscanOutput.uscan_die("Please install gpgv or gpgv2.")
        if not self.gpg:
            UscanOutput.uscan_die("Please install gnupg or gnupg2.")

        # Handle deprecated binary keyrings and convert them if necessary
        self.handle_keyring()

    def find_executable(self, executables):
        """
        Find the first executable that exists in the system.
        """
        for exe in executables:
            path = shutil.which(exe)
            if path:
                return path
        return None

    def handle_keyring(self):
        """
        Handle deprecated binary keyrings and convert them to armored format if necessary.
        """
        keyring_path = Path('debian/upstream/signing-key.asc')

        # Check if armored key exists
        if keyring_path.exists():
            self.keyring = str(keyring_path)
        else:
            # Look for deprecated binary keyrings
            deprecated_keyrings = [
                'debian/upstream/signing-key.pgp',
                'debian/upstream-signing-key.pgp'
            ]
            binkeyring = next((k for k in deprecated_keyrings if Path(k).exists()), None)

            if binkeyring:
                os.makedirs('debian/upstream', mode=0o700, exist_ok=True)
                UscanOutput.uscan_verbose(f"Found upstream binary signing keyring: {binkeyring}")

                # Convert to armored key
                self.keyring = 'debian/upstream/signing-key.asc'
                UscanOutput.uscan_warn(
                    f"Found deprecated binary keyring ({binkeyring}). "
                    f"Please save it in armored format in {self.keyring}. "
                    "For example:\n   gpg --output {self.keyring} --enarmor {binkeyring}"
                )

                # Convert binary keyring to armored format
                self.spawn_gpg_command([
                    self.gpg, '--homedir', '/dev/null', '--no-options', '-q', '--batch',
                    '--no-default-keyring', '--output', self.keyring, '--enarmor', binkeyring
                ])
                UscanOutput.uscan_warn(f"Generated upstream signing keyring: {self.keyring}")
                shutil.move(binkeyring, f"{binkeyring}.backup")
                UscanOutput.uscan_verbose(f"Renamed upstream binary signing keyring: {binkeyring}.backup")

        # Convert armored key to binary for use by gpgv
        if self.keyring and self.keyring.endswith('.asc'):
            self.gpghome = tempfile.mkdtemp()
            new_keyring = os.path.join(self.gpghome, 'trustedkeys.gpg')
            self.spawn_gpg_command([
                self.gpg, '--homedir', self.gpghome, '--no-options', '-q', '--batch',
                '--no-default-keyring', '--output', new_keyring, '--dearmor', self.keyring
            ])
            self.keyring = new_keyring

    def spawn_gpg_command(self, command):
        """
        Run the provided gpg command and handle errors.
        """
        result = subprocess.run(command, capture_output=True)
        if result.returncode != 0:
            UscanOutput.uscan_die(f"Error running command: {' '.join(command)}\n{result.stderr.decode()}")

    def verify(self, sigfile, newfile):
        """
        Verifies the OpenPGP signature of a file using gpgv and extracts the signature.
        """
        UscanOutput.uscan_verbose(f"Verifying OpenPGP self-signature of {newfile} and extracting {sigfile}")

        result = subprocess.run([
            self.gpgv, '--homedir', self.gpghome, '--keyring', self.keyring, '-o', sigfile, newfile
        ], capture_output=True)

        if result.returncode != 0:
            UscanOutput.uscan_die("OpenPGP signature did not verify.")

    def verifyv(self, sigfile, base):
        """
        Verifies the OpenPGP signature of a file using gpgv.
        """
        UscanOutput.uscan_verbose(f"Verifying OpenPGP signature {sigfile} for {base}")

        result = subprocess.run([
            self.gpgv, '--homedir', '/dev/null', '--keyring', self.keyring, sigfile, base
        ], capture_output=True)

        if result.returncode != 0:
            UscanOutput.uscan_die("OpenPGP signature did not verify.")

    def verify_git(self, gitdir, tag, git_upstream=False):
        """
        Verifies a GPG-signed Git tag by checking the signature of the tag in the Git repository.
        """
        commit = self.git_show_ref(gitdir, tag, git_upstream)
        file_content = self.git_cat_file(gitdir, commit, git_upstream)
        signature, text = self.extract_signature(file_content)

        with tempfile.TemporaryDirectory() as tempdir:
            sigfile_path = os.path.join(tempdir, 'sig')
            txtfile_path = os.path.join(tempdir, 'txt')

            with open(sigfile_path, 'w') as sigfile, open(txtfile_path, 'w') as txtfile:
                txtfile.write(text)
                sigfile.write(signature)

            result = subprocess.run([
                self.gpgv, '--homedir', self.gpghome, '--keyring', self.keyring, sigfile_path, txtfile_path
            ], capture_output=True)

            if result.returncode != 0:
                UscanOutput.uscan_die("OpenPGP signature did not verify.")

    def git_show_ref(self, gitdir, tag, git_upstream=False):
        """
        Get the commit corresponding to a Git tag.
        """
        command = ['git', '--git-dir', gitdir] if not git_upstream else ['git']
        command += ['show-ref', tag]
        result = subprocess.run(command, capture_output=True)

        if result.returncode != 0:
            UscanOutput.uscan_die("git tag not found")

        commit = result.stdout.decode().split()[0]
        return commit

    def git_cat_file(self, gitdir, commit, git_upstream=False):
        """
        Get the content of a Git object (commit, tag) by its hash.
        """
        command = ['git', '--git-dir', gitdir] if not git_upstream else ['git']
        command += ['cat-file', '-p', commit]
        result = subprocess.run(command, capture_output=True)

        if result.returncode != 0:
            UscanOutput.uscan_die("Error retrieving git commit content")

        return result.stdout.decode()

    def extract_signature(self, file_content):
        """
        Extract the OpenPGP signature from a Git tag object.
        """
        match = re.search(r"^(.*?\n)(\-+\s*BEGIN PGP SIGNATURE\s*\-+.*)$", file_content, re.DOTALL)

        if not match:
            UscanOutput.uscan_die("Tag is not signed")

        text = match.group(1)
        signature = match.group(2)
        return signature, text
