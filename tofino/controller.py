import os
import sys
import pdb
import logging
import math
import time

import bfrt_grpc.client as gc
from tabulate import tabulate
import argparse
from pathlib import Path

SDE_INSTALL   = os.environ['SDE_INSTALL']

PYTHON3_VER   = '{}.{}'.format(
    sys.version_info.major,
    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                             'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

MAX_HOPS=256
NUM_PIPES=2
MAX_DEGREE=256

class LocalClient:
    def __init__(self, probs_path, num_hops=MAX_HOPS):        
        self.probs_path = probs_path
        self.num_hops = num_hops

        self._setup()

    def parse_monitored(self, path):
        probs_a = [0]*self.num_hops*MAX_DEGREE
        probs_cum = [0]*self.num_hops*MAX_DEGREE
        
        path = str(path)
        print('Parsing monitored probabilities from file: ', path)
        with open(path, 'r') as f:
            hop = 0
            for line in f:
                line = line.strip().split(',')
                for degree in range(len(line)//2):
                    probs_a[hop*MAX_DEGREE + degree] = int(float(line[degree*2])*pow(2,32))
                    # validate approximation is good
                    assume_val = float(probs_a[hop*MAX_DEGREE + degree])/pow(2,32)
                    if abs(assume_val - float(line[degree*2])) > 0.0001:
                        print('Warning: approximation error too high for hop ', hop, ' degree ', degree)
                    probs_cum[hop*MAX_DEGREE + degree] = int(float(line[degree*2 + 1])*pow(2,32))
                    assume_val = float(probs_cum[hop*MAX_DEGREE + degree])/pow(2,32)
                    if abs(assume_val - float(line[degree*2 + 1])) > 0.0001:
                        print('Warning: approximation error too high for hop ', hop, ' degree ', degree)
                hop += 1
        return probs_a, probs_cum

    def populate_probs(self, probs_a, probs_cum):
        logging.info('Populating probabilities tables...')

        keys = []
        data_a = []
        data_cum = []
        keys_a = [self.probs_a.make_key([gc.KeyTuple('$REGISTER_INDEX', i)]) for i in range(len(probs_a))]
        keys_cum = [self.probs_cum.make_key([gc.KeyTuple('$REGISTER_INDEX', i)]) for i in range(len(probs_cum))]

        data_a_name = self.probs_a.info.data_dict_allname['f1']
        data_cum_name = self.probs_cum.info.data_dict_allname['f1']

        data_a = [self.probs_a.make_data([gc.DataTuple(data_a_name, prob)]) for prob in probs_a]
        data_cum = [self.probs_cum.make_data([gc.DataTuple(data_cum_name, prob)]) for prob in probs_cum]

        self.probs_a.entry_add(self.dev_tgt, keys_a, data_a)
        self.probs_cum.entry_add(self.dev_tgt, keys_cum , data_cum)

        logging.info('Populated probabilities tables.')
       
    def populate_idx(self):
        logging.info('Populating index table...')

        for hop in range(0, MAX_HOPS):
            key = self.base_idx.make_key([gc.KeyTuple('meta.hop_count', hop)])
            hop_degree = hop * MAX_DEGREE
            data = self.base_idx.make_data([gc.DataTuple('idx', hop_degree)], 'Ingress.set_base')
            self.base_idx.entry_add(self.dev_tgt, [key], [data])

        logging.info('Populated index table.')

    def _setup(self):
        bfrt_client_id = 0

        self.interface = gc.ClientInterface(
            grpc_addr = 'localhost:50052',
            client_id = bfrt_client_id,
            device_id = 0,
            num_tries = 1)

        self.bfrt_info = self.interface.bfrt_info_get()
        self.interface.bind_pipeline_config(self.bfrt_info.p4_name_get())
        self.dev_tgt = gc.Target(0)
        print('The target runs the program ', self.bfrt_info.p4_name_get())

        # probabilities tables (these are max_degree * max_hops size)
        self.probs_a = self.bfrt_info.table_get('pipe.Ingress.probs_a')
        self.probs_cum = self.bfrt_info.table_get('pipe.Ingress.probs_cum')
        parsed_probs_a, parsed_probs_cum = self.parse_monitored(self.probs_path)
        self.populate_probs(parsed_probs_a, parsed_probs_cum)

        # idx table
        self.base_idx = self.bfrt_info.table_get('pipe.Ingress.base_idx')
        self.populate_idx()
        

if __name__ == "__main__":
    print("Start Controller....")
    
    logging.basicConfig(level="DEBUG",
                        format="%(asctime)s|%(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    parser = argparse.ArgumentParser()
    parser.add_argument('--probs_path', required=True, type=str, help='Path to probabilities files')
    parser.add_argument('--num_hops', type=int, default=MAX_HOPS, help='Number of hops to monitor')

    args = parser.parse_args()

    client = LocalClient(args.probs_path, args.num_hops)

    # example usage:
    # python3 controller.py --probs_path ../APA/robust64_1.txt --num_hops 64
