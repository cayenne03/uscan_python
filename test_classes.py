from devscript.DevOutput import DevOutput
from devscript.uscan.UscanOutput import UscanOutput
from devscript.uscan.CatchRedirections import CatchRedirections
from pprint import pprint as pp


if __name__ == "__main__":
    # CatchRedirections.pm
    #
    # session = CatchRedirections()
    # response = session.get("https://eu.httpbin.org/absolute-redirect/7") #, allow_redirects=True)
    # pp(session.get_redirections())

    # devscript.DevOutput.pm
    #
    # DevOutput.verbose = 3
    # DevOutput.ds_debug(msg="Hello from `ds_debug`")
    # print(DevOutput.who_called())
    # DevOutput.ds_extra_debug(msg="Hello from `ds_extra_debug`")
    # DevOutput.ds_warn(msg="Hello from `ds_warn`")
    # DevOutput.ds_error(msg="Hello from `ds_error`")

    # devscript.uscan.UscanOutput.pm
    UscanOutput.set_verbose(level=2)
    UscanOutput.uscan_verbose(msg="1 Hello from `uscan_verbose`")
    UscanOutput.uscan_debug(msg="2 Hello from `uscan_debug`")
    UscanOutput.uscan_warn(msg="3 Hello from `uscan_warn`")
    UscanOutput.uscan_msg(msg="4 Hello from `uscan_msg`")

