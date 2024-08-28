import os
import sys
import time
from datetime import timedelta, datetime

import argparse
import yaml
from yaml import Loader

from datagen import CyberDataGenerator

def main():
    # print(type(CyberDataGenerator.CyberDataGenerator))

    parser = argparse.ArgumentParser(description='Generate sample data')
    parser.add_argument('config', type=argparse.FileType('r'), help='Config file')
    parser.add_argument('--gpu', type=bool, help='GPU vs CPU data gen', default=True)
    parser.add_argument('--streaming', type=bool, help='Generate data fast or at the defined interval', default=False)
    args = parser.parse_args()

    config = {}
    if args.config:
        conf_abs_path = os.path.dirname(os.path.abspath(args.config.name))
        sys.path.append(conf_abs_path)
        config = yaml.load(args.config, Loader=Loader)
        config['conf_abs_path'] = conf_abs_path

    period_type = config['interval'][-1]
    period = int(config['interval'][:-1])

    config['period_type'] = period_type
    config['period'] = period

    if args.streaming:
        from progressbar import progressbar

    if period_type == 'm':
        delta = timedelta(minutes=period)
        config['max_time'] = 60
    elif period_type == 'h':
        delta = timedelta(hours=period)
        config['max_time'] = 3600

    start, end = datetime.strptime(config['start_date'], '%Y-%m-%d'), datetime.strptime(config['end_date'], '%Y-%m-%d') + timedelta(days=1)
    current_period = start

    gen = CyberDataGenerator(config, args.gpu)

    current_hour = 0
    try:
        while current_period < end:
            now = time.monotonic()

            if current_period.hour != current_hour:
                print(current_period)
                current_hour = current_period.hour
            
            gen.generate_records(current_period)

            if args.streaming:
                prefix = f'Waiting... Current period: {datetime.strftime(current_period, "%Y-%m-%d %H:%M:%S")} '
                for _ in progressbar(range(int(60 + (now - time.monotonic()))), prefix=prefix):
                    time.sleep(1)
            
            current_period = current_period + delta
    except KeyboardInterrupt:
        print('\nTerminating the datagen...')

        # clean up and release the GPU mem
        del gen


if __name__ == '__main__':
    main()
