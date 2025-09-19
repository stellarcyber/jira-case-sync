__version__ = '20250516.000'

import logging

"""
Provides utilitarian methods for general stellar cyber usage.

    version:    20250430.000    initial 
                20250516.000    added webhook ingestion default sender / async

"""

import logging.handlers
import sys
import requests
from time import time
import threading
# from concurrent.futures import ThreadPoolExecutor


class logger_util:

    def __init__(self, args):
        l = logging.getLogger(__name__)
        l_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        l_handler = logging.StreamHandler(sys.stdout)
        l_handler.setFormatter(l_format)
        l.addHandler(l_handler)
        l.setLevel(logging.INFO)

        if args.verbose:
            l.setLevel(logging.DEBUG)
        if args.logfile:
            f_handler = logging.handlers.RotatingFileHandler(args.logfile, maxBytes=(1048576 * 5), backupCount=5)
            f_handler.setFormatter(l_format)
            l.addHandler(f_handler)

        self.l = l
        self.webhook_url = ''
        self.webhook_key = ''
        self.webhook_cert_verify = True
        self.slack_endpoint = ''
        self.l.info('logger_util version: [{}]'.format(__version__))

    def configure(self, config={}):
        ''' config entries for webhook ingestion '''
        self.webhook_url = config.get('webhook_ingest_url', '')
        self.webhook_key = config.get('webhook_ingest_key', '')
        self.webhook_cert_verify = config.get('webhook_cert_verify', True)
        if self.webhook_url:
            # self.l.debug("webhook url: [{}] | key: [{}] verify cert: [{}]".format(self.webhook_url, self.webhook_key, self.webhook_cert_verify))
            pass
        self.slack_endpoint = config.get('slack_workflow_url', '')

    def info(self, message, send_to_webhook=True):
        self.l.info(message)
        if send_to_webhook:
            self.send_to_webhook_async({"severity": "info", "message": message})

    def warn(self, message, send_to_webhook=True):
        self.l.warn(message)
        if send_to_webhook:
            self.send_to_webhook_async({"severity": "warn", "message": message})

    def warning(self, message, send_to_webhook=True):
        self.warn(message, send_to_webhook)

    def error(self, message, send_to_webhook=True):
        self.l.error(message)
        if send_to_webhook:
            self.send_to_webhook_async({"severity": "error", "message": message})

    def critical(self, message, send_to_webhook=True):
        self.l.critical(message)
        if send_to_webhook:
            self.send_to_webhook_async({"severity": "critical", "message": message})

    def debug(self, message, send_to_webhook=True):
        self.l.debug(message)
        if send_to_webhook:
            self.send_to_webhook_async({"severity": "debug", "message": message})

    def send_to_webhook_async(self, data=None):
        if self.webhook_url and data:
            thr = threading.Thread(target=self._send_to_webhook, kwargs={"data":data})
            thr.start()
        return

    def _send_to_webhook(self, data=None):
        '''
        send data to xdr connector webhook
        :param data: can be dict or string - if string, then placed as value for "message" key
        :return: None
        '''
        try:
            if self.webhook_url and data:
                if isinstance(data, dict):
                    json_data = data
                else:
                    json_data = {"message": "{}".format(data)}
                json_data['timestamp'] = int(time() * 1000)
                url = "{}".format(self.webhook_url)
                headers = {"Content-Type": "application/json"}
                headers['Authorization'] = "Bearer {}".format(self.webhook_key)
                r = requests.post(url=url, headers=headers, json=json_data, verify=False)
                if 200 <= r.status_code <= 299:
                    # self.l.info("Successfully posted to httpjson forwarder: [{}]".format(url))
                    pass
                else:
                    raise Exception("{}".format(r.text))
        except Exception as e:
            self.l.error("Problem with send_to_webhook: [{}]".format(e))
        return

    def send_to_slack(self, source_dev='', error_msg='', message='', override_default_json={}):
        if not self.slack_endpoint:
            return
        url = self.slack_endpoint
        headers = {"Content-Type": "application/json"}
        if override_default_json:
            data = override_default_json
        else:
            data = {"system": source_dev, "error": error_msg, "message": message}
        r = requests.post(url=url, headers=headers, json=data)
        if 200 <= r.status_code <= 299:
            self.l.info("Successfully posted to slack: [{}]".format(url))
        else:
            self.l.error("Problem posting to slack: [{}]".format(url))

    def send_to_slack_app(self, json_message={}):
        if not self.slack_endpoint:
            return
        url = self.slack_endpoint
        headers = {"Content-Type": "application/json"}
        data = json_message
        r = requests.post(url=url, headers=headers, json=data)
        if 200 <= r.status_code <= 299:
            self.l.info("Successfully posted to slack app: [{}]".format(url))
        else:
            self.l.error("Problem posting to slack app: [{}]".format(url))
