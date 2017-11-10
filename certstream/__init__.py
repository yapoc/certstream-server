import logging

import asyncio

import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from certstream.certlib import MerkleTreeHeader
from certstream.watcher import TransparencyWatcher
from certstream.webserver import WebServer

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.DEBUG)


def run(proxy_string = None, persistance_folder = None):
    logging.info("Starting CertStream...")

    loop = asyncio.get_event_loop()

    watcher = TransparencyWatcher(_loop = loop, proxy_string = proxy_string, persistance_folder = persistance_folder)
    webserver = WebServer(loop, watcher)

    asyncio.ensure_future(asyncio.gather(*watcher.get_tasks()))

    webserver.run_server()

if __name__ == "__main__":
    run()
