#! /usr/bin/python2.7

import os
import sys
import statistics
import json
import time
import redis
import threading
import signal
import argparse
from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily
from prometheus_client import start_http_server

exit=False
config={}

def ipcount(ip):
    return ip["count"]

def worker(collector):
    global exit
    global config

    while True:
        if exit:
            return
        os.system('timeout %s tcpdump -l -i %s "tcp[tcpflags] & tcp-syn != 0 and dst net %s" -nnnn > /tmp/tcpsyn.output 2>/dev/null' % 
                (config["NetowrkCaptureInterval"], config["NetworkInterface"], config["NetworkRange"]))
        with open("/tmp/tcpsyn.output", "r") as fptr:
            lines=fptr.readlines()
            ips={}
            for line in lines:
                if line.strip()=="":
                    continue
                ip=".".join(line.split(" ")[2].split(".")[0:4])
                if ip in config["WhiteList"]:
                    continue
                if ip in ips:
                    ips[ip]+=1
                else:
                    ips[ip]=1
        
        redisHost, redisPort=config["RedisDb"].split(":")
        hostname=config["Hostname"]
        RedisDbName=config["RedisDbName"]
        rclient=redis.Redis(host=redisHost, port=int(redisPort), db=int(RedisDbName))
        rclient.set(hostname, json.dumps(ips))
        rclient.expire(hostname, 60)
        boxes=rclient.keys("*")
        db={}
        for box in boxes:
            boxIPs=json.loads(rclient.get(box))
            for boxIP in boxIPs:
                if boxIP in db:
                    db[boxIP]+=boxIPs[boxIP]
                else:
                    db[boxIP]=boxIPs[boxIP]
        rclient.close()
        result=[{"ip":ip, "count":db[ip]} for ip in db]
        result.sort(key=ipcount, reverse=True)
        num=[item["count"] for item in result]
        print result
        print "-"*10
        print num
        print "-"*10
        collector.setMean(statistics.mean(num))
        collector.setMedian(statistics.median(num))
        collector.setMedianHigh(statistics.median_high(num))
        collector.setMedianLow(statistics.median_low(num))
        collector.setVariance(statistics.variance(num))
        collector.setMax(max(num))
        collector.setSum(sum(num))
        print
        time.sleep(1)

def signal_handler(sig, frame):
    global exit
    exit=True

def load_config(configFile):
    global config

    with open(configFile, "r") as fptr:
        content=fptr.read()

    config=json.loads(content)

class TcpSynCollector(object):
    def __init__(self):
        self.mean=0
        self.median=0
        self.median_high=0
        self.median_low=0
        self.variance=0
        self.max=0
        self.sum=0

    def setMean(self, mean):
        self.mean=mean
        
    def setMedian(self, median):
        self.median=median

    def setMedianHigh(self, medianHigh):
        self.median_high=medianHigh

    def setMedianLow(self, medianLow):
        self.median_low=medianLow

    def setVariance(self, variance):
        self.variance=variance

    def getThreshold(self):
        return self.variance+self.median

    def setMax(self, maxValue):
        self.max=maxValue

    def setSum(self, sumValue):
        self.sum=sumValue

    def collect(self):
        g = GaugeMetricFamily("tcp_syn_stats", 'tcp syn statistics', labels=['type'])
        g.add_metric(['mean'], self.mean)
        g.add_metric(['median'], self.median)
        g.add_metric(['media_high'], self.median_high)
        g.add_metric(['meadian_low'], self.median_low)
        g.add_metric(['variance'], self.variance)
        g.add_metric(['threshold'], self.getThreshold())
        g.add_metric(['max'], self.max)
        g.add_metric(['sum'], self.sum)
        yield g

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument("-c", "--config", required=True, help="path to config file")
    args=parser.parse_args()
    load_config(args.config)
    collector=TcpSynCollector()
    thread=threading.Thread(target=worker, args=(collector,))
    thread.start()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    addr,port=config["Bind"].split(":")
    start_http_server(int(port), addr)
    REGISTRY.register(collector)
    while True:
        if exit:
            break
        time.sleep(1)
