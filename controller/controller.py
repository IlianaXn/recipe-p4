import os
import sys
import pdb
import logging
import math
import time

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
MAX_DEGREE=8

import bfrt_grpc.client as gc
from tabulate import tabulate
import argparse
from pathlib import Path

class LocalClient:
    def __init__(self, probs_path, num_hops=MAX_HOPS):        
        self.probs_path = probs_path
        self.num_hops = num_hops

        self._setup()

    def parse_monitored(self, paths):
        probs_a = [0]*self.num_hops*MAX_DEGREE
        probs_r = [0]*self.num_hops*MAX_DEGREE
        for path in Path('params/').rglob(paths):
            path = str(path)

            with open(path, 'r') as f:
                hop = 0
                for line in f:
                    line = line.strip().split(',')
                    for degree in range(len(line)//2):
                        probs_a[hop*MAX_DEGREE + degree] = int(float(line[degree*2])*pow(2,32))
                        probs_r[hop*MAX_DEGREE + degree] = int(float(line[degree*2 + 1])*pow(2,32))
                    hop += 1
        return probs_a, probs_r


    def _setup(self):
        bfrt_client_id = 0

        self.interface = gc.ClientInterface(
            grpc_addr = 'localhost:50052',
            client_id = bfrt_client_id,
            device_id = 0,
            num_tries = 1)

        self.bfrt_info = self.interface.bfrt_info_get()
        self.dev_tgt = gc.Target(0)
        print('The target runs the program ', self.bfrt_info.p4_name_get())

        # probabilities tables (these are max_degree * max_hops size)
        self.probs_a = self.bfrt_info.table_get('pipe.Ingress.probs_a')
        self.probs_r = self.bfrt_info.table_get('pipe.Ingress.probs_r')
        
        self.interface.bind_pipeline_config(self.bfrt_info.p4_name_get())
        
        parsed_probs_a, parsed_probs_r = self.parse_monitored(self.probs_path)
        self.populate_probs(parsed_probs_a, parsed_probs_r)

    def populate_probs(self, probs_a, probs_r):
        logging.info('Populating probabilities tables...')

        keys = []
        data_a = []
        data_r = []
        keys_a = [self.probs_a.make_key([gc.KeyTuple('$REGISTER_INDEX', i)]) for i in range(len(probs_a))]
        keys_r = [self.probs_r.make_key([gc.KeyTuple('$REGISTER_INDEX', i)]) for i in range(len(probs_r))]

        data_a_name = self.probs_a.info.data_dict_allname['f1']
        data_r_name = self.probs_r.info.data_dict_allname['f1']

        data_a = [self.probs_a.make_data([gc.DataTuple(data_a_name, prob)]) for prob in probs_a]
        data_r = [self.probs_r.make_data([gc.DataTuple(data_r_name, prob)]) for prob in probs_r]

        self.probs_a.entry_add(self.dev_tgt, keys_a, data_a)
        self.probs_r.entry_add(self.dev_tgt, keys_r , data_r)

        logging.info('Populated probabilities tables.')
       
    
    def read_register(self, table, index_range, flags={"from_hw": False}):
        _keys = [table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)]) for index in index_range]
        data_name = table.info.data_dict_allname["f1"]
        results = []
        for entry in table.entry_get(self.dev_tgt, _keys, flags=flags):
            data = entry[0].to_dict()
            results.append(data[data_name])

        return results

    def write_register(self, table, keys_1, keys_0):
        _keys = [table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)]) for index in keys_1]
        _keys.extend([table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)]) for index in keys_0])

        data_name = table.info.data_dict_allname["f1"]
        _data = [table.make_data([gc.DataTuple(data_name, 1)])]*len(keys_1)
        _data.extend([table.make_data([gc.DataTuple(data_name, 0)])]*len(keys_0))

        table.entry_add(self.dev_tgt, _keys, _data)

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
    client.get_gen_info()