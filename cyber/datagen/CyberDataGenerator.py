from datetime import timedelta, datetime
import random
import os
import sys
from dotenv import load_dotenv

import yaml
from yaml import Loader
import boto3
from botocore.exceptions import ClientError

load_dotenv(dotenv_path="aws_creds.env")

gpu_gen = True
if gpu_gen:
    import cupy as numeric
    import cudf as dataframe
else:
    import numpy as numeric
    import pandas as dataframe


class CyberDataGenerator:
    def __init__(self, config, gpu_gen=True):

        self.config = config
        self.protocols = dataframe.DataFrame(self.config['metadata']['protocols'], columns=['Protocol']).reset_index()
        self.flags = dataframe.DataFrame(self.config['metadata']['flags'], columns=['Flags']).reset_index()
        self.user_ips = dataframe.read_csv(self.config['metadata']['user_device_ip'])#.reset_index()
        self.dns_lookup = dataframe.read_csv(self.config['metadata']['dns_lookup'], sep='|').reset_index()
        self.dns_servers = dataframe.read_csv(self.config['metadata']['dns_servers'], sep='|').reset_index()
        self.dns_queries = dataframe.DataFrame(self.config['metadata']['dns_query_types'], columns=['QueryType']).reset_index()
        self.write_folder = self.config['destination']
        self.max_time = self.config['max_time']
        self.s3_bucket = 'voltrondata-cyber-security-demo-us-east-2'

        self._prep_dns_meta()

    def _prep_dns_meta(self):
        dns_response = self.config['metadata']['dns_response']
        resp_choices = len(dns_response['code'])
        resp_probs = numeric.array(dns_response['weights'])
        self.dns_response = {
            'choices_len': resp_choices, 
            'p': resp_probs, 
            'codes': dataframe.DataFrame(dns_response['code'], columns=['DNS_Response']).reset_index()
        }
        
        dns_query_type = self.config['metadata']['dns_query_types']
        qt_choices = len(dns_query_type['code'])
        qt_probs = numeric.array(dns_query_type['weights'])
        self.dns_query_type = {
            'choices_len': qt_choices, 
            'p': qt_probs,
            'codes': dataframe.DataFrame(dns_query_type['code'], columns=['DNS_QueryType']).reset_index()
        }
        
    def generate_records(self, timestamp):
        # how many records
        no_of_records = int(numeric.random.uniform(self.config['min_records'], self.config['max_records']))

        # is it an attack?
        attack = self._is_it_attack()
        
        if attack:
            attack_meta = self._what_kind_of_attack()        
            perpetrators, target = self._whos_attacking_who(attack_meta)

        # generate the nflow records
        nflow_df = self._generate_nflow(no_of_records, timestamp)

        if attack:
            # how many records
            no_of_attack_records = int(numeric.random.uniform(self.config['min_records'], self.config['max_records']))
            nflow_attack_df = self._generate_nflow(no_of_attack_records, timestamp, attack_meta, perpetrators, target)

            nflow_df = dataframe.concat([nflow_df, nflow_attack_df]).reset_index(drop=True)
            no_of_records = no_of_records + no_of_attack_records
            
        # generate the dns records
        dns_df = self._generate_dns(no_of_records, nflow_df)

        # save the data
        fname_suffix = datetime.strftime(timestamp, '%Y%m%d_%H%M')
        self._save_data(nflow_df, dns_df, fname_suffix)

    def _save_data(self, nflow_df, dns_df, fname_suffix):
        nflow_cols_to_keep=[
            'Timestamp', 'Duration_s', 'Protocol', 
            'Origin_IP', 'Destination_IP',
            'Flags', 'Packets', 'Bytes',
            'BPS', 'BPP', 'device', 'user_id'
        ]

        dns_cols_to_keep = ['Timestamp', 'Origin_IP', 'Destination_IP', 'Domain', 
            'DNS_Name', 'DNS_Primary', 'DNS_Secondary',
            'DNS_Response', 'DNS_QueryType', 'Response_ms']

        # define paths
        partitions = fname_suffix.split('_')
        partitions[-1] = partitions[-1][0:2] + '00'

        ### FLATTEN THE PARTITIONING
        partitions = [partitions[0],]

        nflow_path_log  = f'{self.write_folder}/nflow/log/{"/".join(partitions)}'
        nflow_path_parquet = f'{self.write_folder}/nflow/parquet/{"/".join(partitions)}'
        nflow_parquet_fname = f'{nflow_path_parquet}/nflow_{fname_suffix}.parquet'
        if not os.path.exists(nflow_path_log):
            os.makedirs(nflow_path_log)

        if not os.path.exists(nflow_path_parquet):
            os.makedirs(nflow_path_parquet)

        dns_path_log  = f'{self.write_folder}/dns/log/{"/".join(partitions)}'
        dns_path_parquet = f'{self.write_folder}/dns/parquet/{"/".join(partitions)}'
        dns_parquet_fname = f'{dns_path_parquet}/dns_{fname_suffix}.parquet'
        if not os.path.exists(dns_path_log):
            os.makedirs(dns_path_log)
        if not os.path.exists(dns_path_parquet):
            os.makedirs(dns_path_parquet)

        nflow_df[nflow_cols_to_keep].rename(columns={'device': 'Device', 'user_id': 'User_ID'}).to_csv(f'{nflow_path_log}/nflow_{fname_suffix}.log', sep='|', index=False)
        dns_df[dns_cols_to_keep].to_csv(f'{dns_path_log}/dns_{fname_suffix}.log', sep='|', index=False)

        nflow_df[nflow_cols_to_keep].rename(columns={'device': 'Device', 'user_id': 'User_ID'}).to_parquet(nflow_parquet_fname, index=False, compression='ZSTD')
        dns_df[dns_cols_to_keep].to_parquet(dns_parquet_fname, index=False, compression='ZSTD')

        s3_client = boto3.client('s3')
        s3_nflow_path = f'{self.s3_bucket}/nflow/parquet/{"/".join(partitions)}'
        s3_dns_path = f'{self.s3_bucket}/dns/parquet/{"/".join(partitions)}'

        try:
            nflow_object_name = f'cyber/nflow/parquet/{"/".join(partitions)}/' + os.path.basename(nflow_parquet_fname)
            dns_object_name = f'cyber/dns/parquet/{"/".join(partitions)}/' + os.path.basename(dns_parquet_fname)
            nflow_response = s3_client.upload_file(nflow_parquet_fname, self.s3_bucket, nflow_object_name)
            dns_response = s3_client.upload_file(dns_parquet_fname, self.s3_bucket, dns_object_name)

        except ClientError as e:
            logging.error(e)
            return False

    def _is_it_attack(self):
        return int(numeric.random.choice(2, p=[1-self.config['attacks']['attack_prob'],self.config['attacks']['attack_prob']], size=1)[0])

    def _what_kind_of_attack(self):
        # figure out if DoS or DDoS and who's being attacked
        attack_types = list(self.config['attacks']['attack_type'].items())
        attack_type_choices, attack_type_probs = zip(*attack_types)
        attack_type = attack_type_choices[int(numeric.random.choice(2, p=attack_type_probs, size=1)[0])]
        
        attack_targets = list(self.config['attacks']['attack_target'].items())
        attack_target_choices, attack_target_probs = zip(*attack_targets)
        attack_target = attack_target_choices[int(numeric.random.choice(2, p=attack_target_probs, size=1)[0])]
        
        return (attack_type, attack_target)

    def _whos_attacking_who(self, attack_info):
        return self._pick_attacker_target(*attack_info)
        
    def _pick_attacker_target(self, attack_type, attack_target):
        target = None

        if attack_type == 'DoS':
            perpetrators = self.user_ips.sample(1)
        else:
            if attack_target == 'DNS':
                dns_ip = self.user_ips.sample(1)['DNS_Primary'].to_arrow().to_pylist()[0]
                perpetrators = self.user_ips.where(self.user_ips['DNS_Primary'] == dns_ip).dropna().sample(random.randint(2,8))
            else:
                perpetrators = self.user_ips.sample(random.randint(2,8))
        
        if attack_target == 'DOMAIN':
            target = self.dns_lookup.sample(1)
            
        return (perpetrators[['index','user_id', 'ipaddress', 'DNS_Primary']], target)

    def _pick_target(self, attack_target, perpetrators):
        if attack_target == 'DNS':
            target = perpetrators['DNS'].sample(1)
        else:
            target = self.dns_lookup.sample(1)

        return target

    def _assign_dns(self):
        no_of_users = self.user_ips['index'].count()
        no_of_dns = self.dns_servers['index'].count()
        dns = numeric.random.randint(0, no_of_dns, (no_of_users))

        self.user_ips['dns_idx'] = dns
        self.user_ips = self.user_ips.merge(self.dns_servers, how='left', left_on='dns_idx', right_on='index')
        self.user_ips = self.user_ips.drop(columns=['index_x','index_y','dns_idx']).reset_index()
        self.user_ips.to_csv('conf/common/cyber/user_device_ipaddress_dns.csv', index=False)

    def _generate_dns(self, no_of_records, records_df):
        dns_cols = {
            'Timestamp': 'Timestamp',
            'ipaddress': 'Origin_IP',
            'ip': 'Destination_IP',
            'Domain': 'Domain',
            'user_id': 'user_id',
            'device': 'device'
        }

        dns = records_df[list(dns_cols.keys())].reset_index(drop=True)
        dns = dns.merge(self.user_ips, how='left', on=['device','user_id','ipaddress'])

        # response and query types
        dns['response_code_idx'] = numeric.random.choice(self.dns_response['choices_len'], size=no_of_records, p=self.dns_response['p'])
        dns['query_type_idx'] = numeric.random.choice(self.dns_query_type['choices_len'], size=no_of_records, p=self.dns_query_type['p'])

        dns = dns.merge(self.dns_response['codes'], how='left', left_on='response_code_idx', right_on='index')
        dns = dns.merge(self.dns_query_type['codes'], how='left', left_on='query_type_idx', right_on='index')
        
        # DNS response time
        dns['Response_ms'] = numeric.random.lognormal(0, 0.25, no_of_records) * 20
        
        dns = dns.rename(columns=dns_cols)
        
        return dns

    def _generate_nflow(self, no_of_records, timestamp, attack_meta=None, perpetrators=None, target=None):
        if attack_meta is not None:
            origin_ip = numeric.random.choice(perpetrators['index'].to_cupy(), (no_of_records,1))

            if attack_meta[1] == 'DOMAIN':
                destination_ip = numeric.random.choice(target['index'].to_cupy(), (no_of_records,1))
            else:
                destination_ip = numeric.random.randint(0, len(self.user_ips), (no_of_records,1))
        else:
            origin_ip = numeric.random.randint(0,   len(self.user_ips), (no_of_records,1))
            destination_ip = numeric.random.randint(0,   len(self.user_ips), (no_of_records,1))
            
        records = numeric.random.uniform(0, self.max_time, (no_of_records,1))                                                          # Timestamp (seconds)
        records = numeric.append(records, numeric.random.uniform(0.1, 60, (no_of_records,1)), axis=1)                                  # Duration (seconds)
        records = numeric.append(records, numeric.random.randint(0,   len(self.protocols), (no_of_records,1)), axis=1)                 # Protocols
        records = numeric.append(records, origin_ip, axis=1)                                                                           # Origin IP
        records = numeric.append(records, numeric.random.randint(1,   65534, (no_of_records,1)), axis=1)                               # Origin port
        records = numeric.append(records, destination_ip, axis=1)                                                                      # Destination IP
        records = numeric.append(records, numeric.random.randint(1,   65534, (no_of_records,1)), axis=1)                               # Destination port
        records = numeric.append(records, numeric.random.randint(0,   len(self.flags), (no_of_records,1)), axis=1)                     # Flags
        records = numeric.append(records, numeric.random.randint(10,  250, (no_of_records,1)), axis=1)                                 # Packets
        records = numeric.append(records, numeric.random.randint(500, 5000, (no_of_records,1)), axis=1)                                # Bytes
        records_df = dataframe.DataFrame(
            records, 
            columns=[
                'Timestamp', 'Duration_s', 'Protocol_idx', 
                'Origin_IP_idx', 'Origin_port', 
                'Destination_IP_idx', 'Destination_port', 
                'Flags_idx', 'Packets', 'Bytes'
            ]
        )
        records_df['BPS'] = (records_df['Bytes'] / records_df['Duration_s']).round().astype('int64')
        records_df['BPP'] = (records_df['Bytes'] / records_df['Packets']).round().astype('int64')

        ## produce proper timestamp
        records_df['Timestamp'] = (records_df['Timestamp'] * 1000).astype('<m8[ms]')
        records_df['temp'] = timestamp
        records_df['Timestamp'] = records_df['Timestamp'] + records_df['temp']

        ## get the protocol
        records_df = records_df.merge(self.protocols, how='left', left_on='Protocol_idx', right_on='index')

        ## get the source IP and combine with port
        records_df = records_df.merge(self.user_ips[['index', 'ipaddress', 'device', 'user_id']], how='left', left_on='Origin_IP_idx', right_on='index')
        records_df['Origin_port'] = records_df['Origin_port'].astype('int32').astype('str')
        records_df['Origin_IP'] = records_df['ipaddress'] + ':' + records_df['Origin_port']

        ## get the destination IP and combine with port
        records_df = records_df.merge(self.dns_lookup, how='left', left_on='Destination_IP_idx', right_on='index')
        records_df['Destination_port'] = records_df['Destination_port'].astype('int32').astype('str')
        records_df['Destination_IP'] = records_df['ip'] + ':' + records_df['Destination_port']

        ## get the flags
        records_df = records_df.merge(self.flags, how='left', left_on='Flags_idx', right_on='index')

        ## correct some dtypes
        records_df['Packets'] = records_df['Packets'].astype('int64')
        records_df['Bytes'] = records_df['Bytes'].astype('int64')

        return records_df