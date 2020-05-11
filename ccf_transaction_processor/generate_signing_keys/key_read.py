# Copyright (c) Intel Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
from infra.clients import CCFClient
import argparse
import time
import os
import subprocess
import requests
import time

def run(args):
    # SNIPPET_START: parsing

    num_pings = args.num_pings
    host = args.host
    port = 6006
    cert = "./user1_cert.pem"
    key = "./user1_privk.pem"
    cafile="./networkcert.pem"
    format = "json"


    client = CCFClient(host, port, cert=cert, key=key, ca = cafile, format=format, prefix="users", description="none", \
        version="2.0",connection_timeout=3, request_timeout=3)

    r=client.rpc("get_ledger_verifying_key", dict())
    if r.result:
       print(r.result)
    else:
       print(r.error['message'])

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    

    parser.add_argument(
        "--num-pings",
        help="Number of ping operations to do",
        default = 1000,
        type=int)

    parser.add_argument(
            "--host",
            help="IP address of the CCF service",
            type=str)



    args = parser.parse_args()
    run(args)
