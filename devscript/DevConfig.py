import os
import sys
import re
from pathlib import Path
import argparse
import subprocess
from DevOutput import DevOutput


class DevConfig:
    def __init__(self):
        self.common_opts = [
            ['help', None, lambda args: self.usage() if args.help else None]
        ]
        self.modified_conf_msg = ''
        self.config_files = ['/etc/devscripts.conf', str(Path.home() / '.devscripts')]

    def keys(self):
        raise NotImplementedError("conffile_keys() must be defined in subclasses")

    def parse(self):
        self.parse_conf_files()
        self.parse_command_line()
        self.check_rules()
        return self

    def set_default(self):
        keys = self.keys()
        for key in keys:
            kname, name, check, default = key
            if default is None:
                continue
            # Remove leading '--' and replace hyphens with underscores
            kname = kname.lstrip('--').replace('-', '_').split('!', 1)[0]
            if callable(default):
                self.__dict__[kname] = default()
            else:
                self.__dict__[kname] = default

    def parse_conf_files(self):
        config_files = ['/etc/devscripts.conf', os.path.expanduser('~/.devscripts')]
        args = sys.argv[1:]

        # Check if --no-conf is passed
        if args and args[0].startswith('--no-conf'):
            self.modified_conf_msg = "  (no configuration files read)"
            args.pop(0)
            return self

        tmp_files = []
        # Handle --conf-file argument
        while args and args[0].startswith('--conf-file'):
            conf_arg = args.pop(0).replace('--conf-file=', '')
            file = conf_arg or args.pop(0)
            if file:
                if not file.startswith('+'):
                    config_files = []
                tmp_files.append(file)
            else:
                DevOutput.ds_die("Unable to parse --conf-file option, aborting parsing")

        config_files.extend(tmp_files)
        config_files = [f for f in config_files if os.path.isfile(f)]

        if config_files:
            keys = self.keys()
            key_names = [k[1] for k in keys if k[1]]

            # Execute shell command to source config files and get key values
            shell_cmd = f"for file in {' '.join(config_files)}; do . \"$file\"; done;"
            shell_cmd += "printf '%s\\0' {}".format(" ".join(f"${k}" for k in key_names))

            result = subprocess.run(['/bin/bash', '-c', shell_cmd], stdout=subprocess.PIPE)
            config_vars = result.stdout.decode().split('\0')

            config_dict = dict(zip(key_names, config_vars))

            for key in keys:
                kname, name, check, default = key
                if not name or not config_dict.get(name):
                    continue

                kname = kname.lstrip('--').replace('-', '_').split('!', 1)[0]

                if check:
                    check = self._subs_check(check, kname, name, default)
                    if callable(check):
                        res, msg = check(self, config_dict[name], kname)
                        if not res:
                            DevOutput.ds_warn(msg)
                            continue
                    elif isinstance(check, str) and re.match(check, config_dict[name]):
                        continue
                    else:
                        DevOutput.ds_die(f"Unknown check type for {name}")

                self.__dict__[kname] = config_dict[name]
                self.modified_conf_msg += f"  {name}={config_dict[name]}\n"

        return self

    def parse_command_line(self):
        parser = argparse.ArgumentParser()
        opts = {}

        # Merge common options and specific keys
        keys = self.common_opts + self.keys()

        # Set default values if necessary
        for key in keys:
            kname, name, check, default = key
            if default and callable(default):
                opts[kname.split('!')[0].replace('-', '_')] = default()

        # Add command-line arguments
        for opt in keys:
            if opt[0]:
                parser.add_argument(opt[0])

        args = parser.parse_args()

        # Validate and set command-line arguments
        for key in keys:
            kname, name, check, default = key
            kname = kname.split('!')[0].replace('-', '_')
            opt_val = getattr(args, kname, None)
            if opt_val:
                if isinstance(opt_val, list) and not opt_val:
                    continue
                if isinstance(opt_val, dict) and not opt_val:
                    continue

                if check:
                    check = self._subs_check(check, kname, name, default)
                    if callable(check):
                        res, msg = check(self, opt_val, kname)
                        if not res:
                            DevOutput.ds_die(f"Bad value for {name}: {msg}")
                self.__dict__[kname] = opt_val

        return self

    def check_rules(self):
        """Check the validation rules and apply them."""
        # Check if this instance has a 'rules' method
        if hasattr(self, 'rules'):
            rules = self.rules()
            if rules:
                for i, rule in enumerate(rules, start=1):
                    res, msg = rule(self)
                    if res:
                        if msg:
                            DevOutput.ds_warn(msg)
                    else:
                        DevOutput.ds_error(msg or f"config rule {i}")
        return self

    def _subs_check(self, check, kname, name, default):
        """Helper function to check boolean-like flags."""
        if check == 'bool':
            # Use different placeholder names to avoid 'duplicate parameter name' error
            return lambda placeholder_1, val, placeholder_2: 1 if val.lower() in ['1', 'yes'] else 0 if val.lower() in ['0', 'no'] else default
        raise ValueError(f"Unknown check type for {name}")

    def usage(self):
        """Switch to the manpage for usage instructions."""
        progname = os.path.basename(__file__).replace('.py', '')
        os.execvp("man", ['man', '-P', '/bin/cat', progname])