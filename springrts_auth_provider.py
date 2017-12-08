# -*- coding: utf-8 -*-

from twisted.internet import defer, threads

import xmlrpclib
import logging

__version__ = "0.1.0"

logger = logging.getLogger(__name__)


class SpringRTSAuthProvider(object):
    __version__ = "0.1"

    def __init__(self, config, account_handler):

        self.log = logger

        self.account_handler = account_handler
        self.xmlrpc_uri = config.uri
        self.proxy = xmlrpclib.ServerProxy(self.xmlrpc_uri)
        self.account_info = None

    @defer.inlineCallbacks
    def check_password(self, user_id, password):
        if not password:
            defer.returnValue(False)

        self.log.info("Got password check for " + user_id)

        localpart = user_id.split(":", 1)[0][1:]

        self.account_info = self.proxy.get_account_info(localpart, password)

        auth = self.account_info.get("status")
        if auth:
            self.log.info("User not authenticated")
            defer.returnValue(False)

        self.log.info("User %s authenticated", user_id)

        registration = False

        if not (yield self.account_handler.check_user_exists(user_id)):
            self.log.info("User %s does not exist yet, creating...", user_id)

            user_id, access_token = (yield self.account_handler.register(localpart=localpart))
            registration = True

            self.log.info("Registration based on XMLRPC data was successful for {}".format(user_id))
        else:
            self.log.info("User {} already exists, registration skipped".format(user_id))

        defer.returnValue(True)

    @staticmethod
    def parse_config(config):
        class _XMLRPCConfig(object):
            pass

        xmlrpc_config = _XMLRPCConfig()

        xmlrpc_config.enabled = config.get("enabled", False)

        # verify config sanity
        _require_keys(config, [
            "uri",
        ])

        xmlrpc_config.uri = config["uri"]

        return xmlrpc_config


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "XMLRPC enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )
