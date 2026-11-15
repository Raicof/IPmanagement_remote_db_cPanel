import logging

# Keep library log output out of the test report (the CLI configures real handlers).
_log = logging.getLogger("remotedb_fw")
_log.addHandler(logging.NullHandler())
_log.propagate = False
