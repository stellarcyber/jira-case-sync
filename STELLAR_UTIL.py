__version__ = '20251022.000'

"""
Provides utilitarian methods for general stellar cyber usage.

    version:    20230530.000    initial 
                20240209.000    auth and header fixes to better capture errors
                20240320.000    added STELLAR_UTIL.update_alert_tag method
                20240409.000    added alert enrichment (adds alert name, url, api endpoint to list of id, index)
                20240412.000    added a number of file handling functions for writing, compressing and purging tmp files
                20240419.000    enhancements to alert normalization
                20240503.000    modified STELLAR_UTIL.get_cases - added tenant_id optional param
                20240515.000    added STELLAR_UTIL.get_tenants
                20240522.000    added STELLAR_UTIL.get_case_alerts - uses the new /alerts endpoint for cases to get all interflow
                20240530.000    modified STELLAR_UTIL.get_cases to use either creation date or modified_at - also to optionally ignore case tag
                20240605.000    added compress method for gzip
                20240610.000    added get_open_tickets method to local_db class
                20240628.000    fixed an issue with sqlite db path
                20240820.000    updated the STELLAR_UTIL.get_case_alerts with option to return only alert title/score
                20240820.001    slight adjustment to STELLAR_UTIL.get_cases for "min_size_auto" accuracy
                20240904.000    STELLAR_UTIL.get_cases - option to ignore cases that were last modified by the API account
                20240912.000    added STELLAR_UTIL.get_case_scores
                20240917.000    added capability to send json records to httpjson logforwarder (send_json_to_sensor)
                20241003.000    added method STELLAR_UTIL.update_stellar_case_severity
                20250220.000    added method STELLAR_UTIL.get_latest_case_score
                20250221.000    added method STELLAR_UTIL.get_API_user_id for comparing case comment authors
                20250225.000    fixed local_db.update_remote_ticket_timestamp with default value for remote ts
                20250225.001    added method STELLAR_UTIL.close_case_alerts as a workaround to close all alerts associated with a case
                20250304.000    added support within the STELLAR_UTIL._request_get for data request payload
                                added support within the STELLAR_UTIL.get_stellar_security_alerts for scroll_id (pagination)
                20250307.000    added method STELLAR_UTIL.update_stellar_record_comment
                20250604.000    added STELLAR_UTIL.user_update_rbac method
                20250609.000    added STELLAR_UTIL.get_user_activity method
                20250610.000    added STELLAR_UTIL._request_delete method, STELLAR_UTIL.del_user method
                20250710.000    added method STELLAR_UTIL.resolve_stellar_case which can add a resolution type and close associated cases
                20250902.000    support for new auth method for user based API key for RBAC policy support   
                20250904.000    updated local_db _init to handle path to database (container persistent volume support)
                                updated STELLAR_UTIL _init to handle path to checkpoint file (container persistent volume support)
                20250912.000    improved the use of the persistent data directory for checkpoint file read/write
                20251016.000    STELLAR_UTIL.update_stellar_case change in behavior - if unknown case status, ignore  
                20251022.000    local_db get ticket linkage updates to return state (open/closed)             
"""

import os, sys
import time
from time import strftime, localtime
from datetime import datetime
import requests
import base64
import json
import urllib3
from enum import Enum
import sqlite3 as sl
import zipfile
import gzip, shutil

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CASE_STATUS(Enum):
    Escalated = "Escalated"
    New = "New"
    In_Progress = "In Progress"
    Resolved = "Resolved"
    Canceled = "Cancelled"

    @property
    def get_list(self):
        for s in self.items():
            print(s)
        return "my list"


class STELLAR_UTIL:

    def __init__(self, logger, config={}, optional_data_path=None):
        """General Stellar Cyber UTIL class.

        logger -- logger object
        config -- dictionary of configuration items
            - stellar_dp:       ip or FQDN of the stellar DP - required if API methods are calls
            - stellar_user:     username associated with the stellar_dp API credentials
            - stellar_api_key   api key associated with the stellar API credentials
            - stellar_saas      useful for determining auth methods and other saas specific variances (default: false)
            - stellar_case_tag  tag to update retrieved cases with (default: ticket_opened)
            - stellar_min_alert_cnt     threshold of minimum number of alerts for cases query (default: disabled)
            - stellar_min_score         minimim case score for cases query (default: 0)
            - initial_run_lookback      on first run, how far back to retrieve cases in days (default: 7)
        """

        self.l = logger
        self.l.info('STELLAR_UTIL version: [{}]'.format(__version__))

        self.headers = {'Content-Type': 'application/json',
                        'Accept': 'application/json;charset=utf-8'
                        }

        self.stellar_dp = config.get('stellar_dp', '')
        self.stellar_fb_user = config.get('stellar_user', '')
        self.stellar_fb_user_id = ''
        self.stellar_fb_api_key = config.get('stellar_api_key', '')
        self.stellar_saas = config.get('stellar_saas', True)
        self.stellar_new_auth = config.get('stellar_new_rbac_user_auth', False)
        self.oauth = {"token": '', "expires": 0}
        self.stellar_case_tag = config.get('stellar_case_tag', 'ticket_opened')
        self.stellar_min_alert_cnt = config.get('stellar_min_alert_cnt', 0)
        self.stellar_min_score = config.get('stellar_min_score', 0)
        self.initial_run_lookback = config.get('initial_run_lookback', 7)
        self.httpjson_forwarder_url = config.get('httpjson_forwarder_url', '')
        self.httpjson_forwarder_onprem = config.get('onprem_logforwarder', True)

        ''' set persistent data path for containerization support '''
        self.data_path = self.get_script_path()
        if optional_data_path:
            if str(optional_data_path).startswith("/"):
                # data path is absolute
                self.data_path = optional_data_path
            else:
                # path is relative to script dir
                self.data_path = "{}/{}".format(self.data_path, optional_data_path)
        if not os.path.exists(self.data_path):
            raise Exception(
                "Data path specified in config does not exist: [{}] - cannot continue".format(self.data_path))

    def get_version(self):
        return __version__

    def get_stellar_interflow(self, stellar_index, stellar_id):
        # headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
        path = '/connect/api/data/{}/_search?q=_id:{}'.format(stellar_index, stellar_id)
        interflow = self._request_get(path)
        hit = {}
        hits = interflow.get('hits', {})
        if hits.get('total', {"value": 0}).get('value', 0):
            hit = hits['hits'][0]
            hit = hit.get('_source', {})
            stellar_url = self.make_stellar_url(event_index=stellar_index, event_id=stellar_id)
            hit['stellar_url'] = stellar_url
        return hit

    def update_stellar_record(self, comment, event_index, event_id):
        ''' only works for onprem versions of stellar - why?? '''
        path = '/connect/api/update_ser'
        # path = '/security_events/{}/{}'.format(event_index, event_id)
        update_rec_data = {
            "index": event_index,
            "_id": event_id,
            "status": "In Progress",
            "comments": "{}".format(comment)
        }
        r = self._request_post(path=path, data=update_rec_data)
        return

    def update_stellar_record_status(self, event_index, event_id, status=None, comment=None):
        ''' adds functionality to the previous 'update_stellar_record' '''
        ''' status can be New", "In Progress", "Cancelled", or "Closed" (default) '''
        if not status:
            status = 'Closed'
        path = '/connect/api/v1/security_events/{}/{}'.format(event_index, event_id)
        update_rec_data = {
            "status": "{}".format(status)
        }
        if comment:
            update_rec_data['comments'] = "{}".format(comment)
        r = self._request_post(path=path, data=update_rec_data)
        return

    def update_stellar_record_comment(self, event_index, event_id, comment):
        ''' adds functionality to the previous 'update_stellar_record' '''
        path = '/connect/api/v1/security_events/{}/{}'.format(event_index, event_id)
        update_rec_data = {"comments": "{}".format(comment)}
        r = self._request_post(path=path, data=update_rec_data)
        return

    def make_stellar_url(self, event_index, event_id):
        if self.stellar_saas:
            ret = "https://{}/alerts/alert/{}/_doc/{}".format(self.stellar_dp, event_index, event_id)
        else:
            ret = "https://{}/detect/event/{}/amsg/{}".format(self.stellar_dp, event_index, event_id)
        return ret

    def make_stellar_alert_api_url(self, event_index, event_id):
        ret = "https://{}/connect/api/data/{}/_search?q=_id:{}".format(self.stellar_dp, event_index, event_id)
        return ret

    def make_stellar_case_url(self, case_id):
        return "https://{}/cases/case-detail/{}".format(self.stellar_dp, case_id)

    def get_stellar_cases(self, from_ts=0, from_ts_checkpoint_file='', tenant_id='', use_modified_at=False,
                          ignore_case_tag=True, ignore_api_user_mods=False, status=None):
        path = "/connect/api/v1/cases?"
        from_cp_file_path = ''
        # from_cp_file is a switch used to force reading timestamp from checkpoint file and takes priority
        if from_ts_checkpoint_file:
            from_cp_file_path = from_ts_checkpoint_file
            from_ts = self.checkpoint_read(filepath=from_cp_file_path)
        # on first run, checkpoint file will be empty and return zero timestamp
        if not from_ts:
            days_ago = 86400 * self.initial_run_lookback * 1000
            from_ts = self._get_ts() - days_ago
        if use_modified_at:
            path += "FROM~modified_at={}".format(from_ts)
        else:
            path += "FROM~created_at={}".format(from_ts)
        if not ignore_case_tag:
            path += "&NOT~tags={}".format(self.stellar_case_tag)
        if self.stellar_min_alert_cnt == "auto":
            path += "&min_size_auto"
        elif self.stellar_min_alert_cnt:
            path += "&min_size_auto={}".format(self.stellar_min_alert_cnt)
        if self.stellar_min_score:
            path += "&FROM~score={}".format(self.stellar_min_score)
        if tenant_id:
            path += "&tenantid={}".format(tenant_id)
        if status:
            path += "&status={}".format(status)

        if ignore_api_user_mods:
            if not self.stellar_fb_user_id:
                stellar_fb_user_data = self.get_user(self.stellar_fb_user)
                self.stellar_fb_user_id = stellar_fb_user_data.get('user_id', '')
            path += "&NOT~modified_by={}".format(self.stellar_fb_user_id)

        self.l.info("Getting cases from ts: [{}]".format(from_ts))
        r = self._request_get(path=path)

        r = r.get('data', {})
        case_count = r.get('total', 0)
        self.l.info("Retrieved case count: [{}]".format(case_count))
        if from_cp_file_path and r:
            self.checkpoint_write(filepath=from_cp_file_path, val=self._get_ts())
        return r

    def get_stellar_case(self, ticket_id, printit=False):
        path = "/connect/api/v1/cases?"
        path += "ticket_id={}".format(ticket_id)
        r = self._request_get(path=path)
        r = r.get('data', {}).get('cases')
        if len(r):
            r = r[0]
        if printit and r:
            rr = json.dumps(r, indent=4)
            print(rr)
            print("mod time: {}".format(strftime('%Y-%m-%d %H:%M:%S', localtime(r['modified_at'] / 1000))))
        return r

    def get_stellar_case_by_id(self, case_id):
        path = "/connect/api/v1/cases/{}".format(case_id)
        r = self._request_get(path=path)
        r = r.get('data', {})
        return r

    def update_stellar_case(self, case_id, case_comment='', case_status=CASE_STATUS.In_Progress.value, update_tag=True):
        if case_comment:
            path = "/connect/api/v1/cases/{}/comments".format(case_id)
            comment_data = {"comment": case_comment}
            self._request_post(path=path, data=comment_data)
        if case_status:
            ''' 20251016.000 - if unknown case status, ignore change '''
            if case_status in [item.value for item in CASE_STATUS]:
                path = "/connect/api/v1/cases/{}".format(case_id)
                status_data = {"status": case_status}
                self._request_put(path=path, data=status_data)
        if update_tag:
            path = "/connect/api/v1/cases/{}".format(case_id)
            status_data = {"tags": {"add": [self.stellar_case_tag]}}
            self._request_put(path=path, data=status_data)
        return

    def update_stellar_case_status(self, case_id, case_status=CASE_STATUS.In_Progress):
        if case_status:
            if not case_status in CASE_STATUS:
                case_status = CASE_STATUS.In_Progress
            path = "/connect/api/v1/cases/{}".format(case_id)
            status_data = {"status": case_status.value}
            self._request_put(path=path, data=status_data)
        return

    def resolve_stellar_case(self, case_id, update_alerts=True, resolution=None):
        status_data = {"status": "Resolved"}
        if update_alerts:
            status_data['update_alerts'] = update_alerts
        if resolution and resolution in ["False Positive", "Benign", "True Positive"]:
            status_data['resolution'] = resolution
        path = "/connect/api/v1/cases/{}".format(case_id)
        self._request_put(path=path, data=status_data)
        return

    def update_stellar_case_severity(self, case_id, case_severity=''):
        if case_severity in ['Critical', 'High', 'Medium', 'Low']:
            path = "/connect/api/v1/cases/{}".format(case_id)
            status_data = {"severity": case_severity}
            self._request_put(path=path, data=status_data)
        return

    def update_stellar_case_comment(self, case_id, case_comment=''):
        if case_comment:
            path = "/connect/api/v1/cases/{}/comments".format(case_id)
            comment_data = {"comment": case_comment}
            self._request_post(path=path, data=comment_data)
        return

    def update_stellar_case_tag(self, case_id, update_tag=''):
        if update_tag:
            path = "/connect/api/v1/cases/{}".format(case_id)
            status_data = {"tags": {"add": [update_tag]}}
            self._request_put(path=path, data=status_data)
        return

    def update_stellar_case_assignee(self, case_id, case_assignee=''):
        path = "/connect/api/v1/cases/{}".format(case_id)
        update_data = {"assignee": "{}".format(case_assignee)}
        r = self._request_put(path=path, data=update_data)
        return r

    def get_stellar_case_assignee(self, case_id):
        case = self.get_stellar_case_by_id(case_id)
        r = case.get('assignee_name', '')
        return r

    def get_case_details_all(self, case_id, ticket_id=''):
        ret_case = {"_id": case_id}
        ret_case['summary'] = self.get_case_summary(case_id=case_id)
        ret_case['comments'] = self.get_case_comments(case_id=case_id)
        ret_case['event_ids'] = self.get_incident_events(ticket_id)
        return ret_case

    def get_case_summary(self, case_id):
        path = "/connect/api/v1/cases/{}/summary?formatted=true".format(case_id)
        self.l.debug("Getting case summary: [{}]".format(case_id))
        r = self._request_get(path=path)
        r = r.get('data', '')
        return r

    def get_case_comments(self, case_id):
        path = "/connect/api/v1/cases/{}/comments".format(case_id)
        self.l.debug("Getting case comments: [{}]".format(case_id))
        r = self._request_get(path=path)
        r = r.get('data', '')
        return r

    def get_case_observables(self, case_id):
        path = "/connect/api/v1/cases/{}/observables".format(case_id)
        self.l.debug("Getting case observables: [{}]".format(case_id))
        r = self._request_get(path=path)
        r = r.get('observables', {})
        return r

    def get_case_scores(self, case_id):
        path = "/connect/api/v1/cases/{}/scores".format(case_id)
        self.l.debug("Getting case scores: [{}]".format(case_id))
        r = self._request_get(path=path)
        r = r.get('data', {})
        return r

    def get_latest_case_score(self, case_id):
        case_scores = self.get_case_scores(case_id)
        previous_score_ts = 0
        latest_score = {}
        for case_score in case_scores:
            this_score_ts = case_score.get('timestamp', 0)
            if this_score_ts > previous_score_ts:
                latest_score = case_score
        return latest_score

    def get_incident_events(self, ticket_id=''):
        """
        legacy way of getting alert ids for a case using the incident API endpoint

        :param ticket_id: case ticket id is the only way for incident alert retrieval
        :return: list of event_ids
        """
        events = []
        if ticket_id:
            incident = self.get_incident(ticket_id)
            events = incident.get('event_ids', [])
        return events

    def get_incident(self, ticket_id, printit=False):
        path = "/connect/api/v1/incidents?ticket_id={}&limit=1".format(ticket_id)
        self.l.debug("Getting incident with ticket id: [{}]".format(ticket_id))
        r = self._request_get(path=path)
        r = r.get('data', {}).get('incidents', [])
        if len(r):
            r = r[0]
        if printit:
            rr = json.dumps(r, indent=4)
            print(rr)
            print("mod time: {}".format(strftime('%Y-%m-%d %H:%M:%S', localtime(r['modified_at'] / 1000))))
        return r

    def get_case_alerts(self, case_id, return_only_alert_names=False):
        """
        uses the new /cases/<id>/alerts endpoint to get all alert interflow
        formats into a list and enriches each with _id and _index
        :param case_id: stellar case id
        :return: list of security alert interflows
        """
        path = "/connect/api/v1/cases/{}/alerts".format(case_id)
        self.l.info("Getting alerts associated with case: [{}]".format(case_id))
        limit = 10
        skip = 0
        alerts = []
        while True:
            loop_path = "{}?limit={}&skip={}".format(path, limit, skip)
            r = self._request_get(path=loop_path)
            docs = r.get('data', {}).get('docs')
            returned_cnt = len(docs)
            skip += returned_cnt
            for doc in docs:
                interflow = doc.get('_source')
                if return_only_alert_names:
                    alert_name = interflow.get('xdr_event', {}).get('display_name', None)
                    alert_score = interflow.get('event_score', '')
                    if alert_name:
                        alerts.append("{} [{}]".format(alert_name, alert_score))
                else:
                    interflow['_id'] = doc.get('_id', '')
                    interflow['_index'] = doc.get('_index', '')
                    alerts.append(interflow)
            if returned_cnt < limit:
                break

        self.l.info("Retrieved alerts: [{}]".format(skip))
        return alerts

    def close_case_alerts(self, case_id):
        """
        uses the new /cases/<id>/alerts endpoint then loop through and close them
        as of 5.4.1, there will be a global UI setting that will do this automatically when cases are closed
        :param case_id: stellar case id
        :return: None
        """
        path = "/connect/api/v1/cases/{}/alerts".format(case_id)
        self.l.info("Getting alerts associated with case: [{}]".format(case_id))
        limit = 10
        skip = 0
        alerts = []
        while True:
            loop_path = "{}?limit={}&skip={}".format(path, limit, skip)
            r = self._request_get(path=loop_path)
            docs = r.get('data', {}).get('docs')
            returned_cnt = len(docs)
            skip += returned_cnt
            for doc in docs:
                interflow = {"_id": doc.get('_id', ''), "_index": doc.get('_index', '')}
                alerts.append(interflow)
            if returned_cnt < limit:
                break

        for alert in alerts:
            ''' close each alert '''
            self.update_stellar_record_status(event_index=alert['_index'], event_id=alert['_id'])

        self.l.info("Closed alerts: [{}] for case: [{}]".format(skip, case_id))
        return

    def get_open_cases(self):
        '''
        used primarily for sync operations
        :return:
        '''
        path = "/connect/api/v1/cases?"
        path += "&tags={}".format(self.stellar_case_tag)
        path += "&status=New,In Progress,Escalated"
        self.l.info("Getting all opened cases")
        r = self._request_get(path=path)
        r = r.get('data', {})
        case_count = r.get('total', 0)
        self.l.info("Retrieved case count: [{}]".format(case_count))
        return r

    def get_stellar_security_alerts(self, from_ts=0, seconds_ago=0, tenant_id="", from_ts_checkpoint_file='', query=''):
        hits_total = 0
        hits_returned = 0
        ret = []
        path = "/connect/api/data/aella-ser-*/_search?scroll=10m&size=100&q="
        scroll_path = "/connect/api/data/_search/scroll"
        from_cp_file_path = ''
        # from_cp_file is a switch used to force reading timestamp from checkpoint file and takes priority
        if from_ts_checkpoint_file:
            from_cp_file_path = from_ts_checkpoint_file
            from_ts = self.checkpoint_read(filepath=from_cp_file_path)
        # on first run, checkpoint file will be empty and return zero timestamp
        if from_ts:
            pass
        elif seconds_ago:
            time_ago = seconds_ago * 1000
            from_ts = self._get_ts() - time_ago
        else:
            days_ago = 86400 * self.initial_run_lookback * 1000
            from_ts = self._get_ts() - days_ago
        path += "(write_time:>{}".format(from_ts)
        if tenant_id:
            path += " AND tenantid:{}".format(tenant_id)
        if query:
            path += " AND {}".format(query)
        path += ")"
        try:
            r = self._request_get(path=path)
            hits_total = r.get('hits', {}).get('total', {}).get('value', 0)
            ret = r.get('hits', {}).get('hits', [])
            hits_returned = len(ret)
            scroll_id = r.get('_scroll_id', 0)
            scroll_query = self._get_scroll_query(scroll_id)
            while hits_returned < hits_total:
                r = self._request_get(path=scroll_path, data=scroll_query)
                rr = r.get('hits', {}).get('hits', [])
                hits_returned += len(rr)
                ret.extend(rr)
            if from_cp_file_path and r:
                self.checkpoint_write(filepath=from_cp_file_path, val=self._get_ts())

        except Exception as e:
            self.l.error("Problem running \"get_stellar_security_alerts\": [{}]".format(e))
            pass

        return hits_total, ret

    def get_stellar_es_query(self, stellar_index="aella-syslog", from_ts=0, to_ts=0, seconds_ago=0, tenant_id="", query=''):
        hits_total = 0
        hits_returned = 0
        ret = []
        path = "/connect/api/data/{}-*/_search?scroll=10m&size=100&q=".format(stellar_index)
        scroll_path = "/connect/api/data/_search/scroll"
        if from_ts:
            pass
        elif seconds_ago:
            time_ago = seconds_ago * 1000
            from_ts = self._get_ts() - time_ago
        else:
            days_ago = 86400 * self.initial_run_lookback * 1000
            from_ts = self._get_ts() - days_ago
        path += "(write_time:>{}".format(from_ts)
        if to_ts:
            path += " AND write_time:<{}".format(to_ts)
        if tenant_id:
            path += " AND tenantid:{}".format(tenant_id)
        if query:
            path += " AND {}".format(query)
        path += ")"
        try:
            r = self._request_get(path=path)
            hits_total = r.get('hits', {}).get('total', {}).get('value', 0)
            ret = r.get('hits', {}).get('hits', [])
            hits_returned = len(ret)
            scroll_id = r.get('_scroll_id', 0)
            scroll_query = self._get_scroll_query(scroll_id)
            while hits_returned < hits_total:
                r = self._request_get(path=scroll_path, data=scroll_query)
                rr = r.get('hits', {}).get('hits', [])
                hits_returned += len(rr)
                ret.extend(rr)

        except Exception as e:
            self.l.error("Problem running \"get_stellar_security_alerts\": [{}]".format(e))
            pass

        return hits_total, ret

    def get_security_alert_names(self, security_alerts=[]):
        '''
        loop through each of the _id, _index and extract the alert name from each
        return the list of alert names
        primary used for remote ticketing system case comments to include with the case details

        :param security_alerts:
        :return: security_alert_names as a list
        '''
        security_alert_names = []
        for sec_alert in security_alerts:
            id = sec_alert.get('_id', None)
            index = sec_alert.get('_index', None)
            if id and index:
                interflow = self.get_stellar_interflow(stellar_index=index, stellar_id=id)
                alert_name = interflow.get('xdr_event', {}).get('display_name', None)
                alert_score = interflow.get('event_score', '')
                if alert_name:
                    security_alert_names.append("{} [{}]".format(alert_name, alert_score))
        return security_alert_names

    def get_security_alert_enrichment(self, security_alerts=[], embed_interflow=False):
        '''
        loop through each of the _id, _index and extract the alert name from each
        return the list of alert names
        primary used for remote ticketing system case comments to include with the case details

        :param security_alerts:
        :return: security_alert_names as a list
        '''

        for sec_alert in security_alerts:
            id = sec_alert.get('_id', None)
            index = sec_alert.get('_index', None)
            # fields to extract from interflow along with their default values (if key does not exist)
            # todo: have these passed in as an object rather than hardcoded
            fields_to_collect = {'event_category': '', 'event_source': '', 'event_type': '', 'event_name': '',
                                 'event_status': 'New', 'xdr_event': {}, 'detected_fields': [], 'detected_values': [],
                                 'engid_device_class': '', 'engid_name': '', 'srcip_usersid': '', 'username': '',
                                 'receive_time': 0}
            if id and index:
                interflow = self.get_stellar_interflow(stellar_index=index, stellar_id=id)
                alert_name = interflow.get('xdr_event', {}).get('display_name', None)
                alert_score = interflow.get('event_score', '')
                if alert_name:
                    sec_alert['alert_name'] = alert_name
                    sec_alert['alert_score'] = alert_score
                    for field_to_collect in fields_to_collect.keys():
                        sec_alert[field_to_collect] = interflow.get(field_to_collect,
                                                                    fields_to_collect[field_to_collect])
                sec_alert['alert_url'] = self.make_stellar_url(event_index=index, event_id=id)
                sec_alert['alert_api'] = self.make_stellar_alert_api_url(event_index=index, event_id=id)
                if embed_interflow:
                    sec_alert['interflow'] = interflow
        return security_alerts

    def update_alert_tags(self, index, id, tag=None):
        '''
        update a security alert with the tag

        :param index:   security alert index
        :param id:      security alert id
        :param tag:     tag to insert
        :return:        True/False for success/failure
        '''
        ret = True
        if not tag:
            tag = self.stellar_case_tag
        path = "/connect/api/v1/security_events/{}/{}".format(index, id)
        data = {"event_tags": [{"op": "add", "tag": "{}".format(tag)}]}
        try:
            r = self._request_post(path=path, data=data)
        except:
            ret = False
        return ret

    def add_case_comment(self, case_id, comment):
        '''
        update a stellar case with the comment

        :param case_id: stellar case id
        :param comment: security alert id
        :return:        True/False for success/failure
        '''
        ret = True
        path = "/connect/api/v1/cases/{}/comments".format(case_id)
        data = {"comment": "{}".format(comment)}
        try:
            r = self._request_post(path=path, data=data)
        except:
            ret = False
        return ret

    def get_tenants(self):
        '''
        get all tenants
        :return: [] list of tenants
        '''
        path = "/connect/api/v1/tenants"
        self.l.info("Getting all tenants")
        r = self._request_get(path=path)
        r = r.get('data', [])
        tenant_cnt = len(r)
        self.l.info("Retrieved tenants: [{}]".format(tenant_cnt))
        return r

    def get_users(self):
        '''
        get all tenants
        :return: [] list of tenants
        '''
        path = "/connect/api/v1/users"
        self.l.info("Getting all users")
        r = self._request_get(path=path)
        r = r.get('data', [])
        user_cnt = len(r)
        self.l.info("Retrieved users: [{}]".format(user_cnt))
        return r

    def get_user(self, email='', user_id=None):
        ret = {}
        if user_id:
            path = "/connect/api/v1/users/{}".format(user_id)
            r = self._request_get(path=path)
            ret = r.get('data', [])
        elif email:
            users = self.get_users()
            for user in users:
                if email == user.get('email'):
                    ret = user
                    break
        return ret

    def del_user(self, user_id=None):
        ret = {}
        if not user_id:
            return ret
        path = "/connect/api/v1/users/{}".format(user_id)
        ret = self._request_delete(path=path)
        return ret

    def get_user_activity(self, data_search='', activity_search='', module_search='', from_ts=0, to_ts=0):
        '''
        Query the user_activities endpoint
        Primary use case is to discover when a certain user account was created, but any use case where
        user activity needs to be searched can work with the appropriate query subject

        NOTE:   this API has a 7 day time limit when from and to timestamps are used
                when called without from and to, time span is very limited (not documented)

        :param data_search: string to be searched for within the data of the activity
        :param activity_search: type of activity, such as "add user"
        :param module_search: module of activity, such as "User"
        :param from_ts: start (earliest) of search (epoch) - must include to_ts
        :param to_ts: end (latest) of search (epoch) - must include from_ts
        :return: list of user activity json records
        '''
        ret = []
        path = "/connect/api/v1/user_activities?sort=Timestamps&order=asc"
        if data_search:
            path += "&Data={}".format(data_search)
        if activity_search:
            path += "&Activity={}".format(activity_search)
        if module_search:
            path += "&module={}".format(module_search)
        if from_ts and to_ts:
            path += "&FROM~Timestamps={}&TO~Timestamps={}".format(from_ts, to_ts)
        r = self._request_get(path=path)
        ret = r.get('activities', [])
        return ret

    def get_API_user_id(self):
        '''
        return the user object for the current API user
        this is needed to obtain the user_id from the username
        because some stellar case objects only include the user_id and not the name
        and if we want to know if the API user made a change to an object, then we need to compare the user ids
        :return: user object assoiated with the API user / key
        '''
        user_email = self.stellar_fb_user
        user_object = self.get_user(email=user_email)
        user_id = user_object.get('user_id', '')
        return user_id

    def user_update_rbac(self, user_id, rbac_id=None):
        '''

        :param user_id: user id associated with the user object
        :param rbac_id: rbac id associated with the RBAC object (use webdev tools)
        :return: user object as json
        '''
        ret = {}
        if not rbac_id:
            self.l.error("No RBAC ID provided. Cannot update user")
            return
        user = self.get_user(user_id=user_id)
        user_rbac_id = user.get('priv_profile_id', '')
        if user_rbac_id == rbac_id:
            msg = "User currently has the same RBAC ID. Not updating."
            self.l.warn(msg)
            ret = {"data": {"warning": msg}}
        else:
            path = "/connect/api/v1/users/{}".format(user_id)
            data = {"priv_profile_id": "{}".format(rbac_id)}
            r = self._request_patch(path=path, data=data)
            ret = r.get('data', [])
        return ret

    def get_license_entities(self, tenant_id='', date='', days_back=0):
        ret = {}
        path = "/connect/api/v1/entity_usages/entity_list/tenant?"
        has_param = False
        if tenant_id:
            path += "cust_id={}".format(tenant_id)
            has_param = True
        if date:
            if has_param:
                path += "&"
            path += "date={}".format(date)
        elif days_back:
            if has_param:
                path += "&"
            path += "days={}".format(days_back)

        self.l.info("Getting license entities")
        r = self._request_get(path=path)
        ret = r.get('data', [])
        return ret

    def get_storage_usages(self, tenant_id='', per_index=False):
        ret = []
        aggr_type = "tenant"
        if per_index:
            aggr_type = "tenant_index"
        path = "/connect/api/v1/storage-usages?aggr_type={}".format(aggr_type)
        if tenant_id:
            path += "&cust_id={}".format(tenant_id)
        self.l.info("Getting storage volume")
        r = self._request_get(path=path)
        ret = r.get('data', [])
        return ret

    def get_connectors(self, tenant_id=None):
        ret = []
        path = "/connect/api/v1/connectors"
        if tenant_id:
            path += "cust_id={}".format(tenant_id)
        self.l.info("Getting connectors")
        r = self._request_get(path=path)
        ret = r.get('connectors', [])
        return ret

    def get_sensors(self, tenant_id=None):
        ret = {}
        path = "/connect/api/v1/data_sensors"
        if tenant_id:
            path += "cust_id={}".format(tenant_id)
        self.l.info("Getting sensors")
        r = self._request_get(path=path)
        ret = r.get('sensors', [])
        return ret

    def checkpoint_write(self, filepath, val=None):
        cp_file_path = "{}/{}".format(self.data_path, filepath)
        if not val:
            val = self._get_ts()
        with open(cp_file_path, "w") as fh:
            fh.write(str(val))

    def checkpoint_read(self, filepath):
        ret = 0
        cp_file_path = "{}/{}".format(self.data_path, filepath)
        try:
            with open(cp_file_path, "r") as fh:
                ret = fh.read()
        except:
            pass
        return ret

    def write_file(self, data, file_path):
        ret = True
        self.l.info("Writing file: {}".format(file_path))
        try:
            with open(file_path, "w") as fh:
                fh.write(data)
        except Exception as e:
            self.l.error("Cannot write file: [{}] [{}]".format(file_path, e))
            ret = False
        return ret

    def compress_file(self, file_path, archive_name='', use_gzip=False):
        self.l.info("Compressing file: {}".format(file_path))

        try:
            if use_gzip:
                zip_file_path = "{}.gz".format(file_path)
                with open(file_path, 'rb') as f_in:
                    with gzip.open(zip_file_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                        f_in.close()
                        os.remove(file_path)
            else:
                zip_file_path = "{}.zip".format(file_path)
                with zipfile.ZipFile(zip_file_path, 'w',
                                     compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.write(file_path, arcname=archive_name)
                    os.remove(file_path)

        except Exception as e:
            self.l.error("Cannot compress file: [{} {}]".format(file_path, e))
            zip_file_path = ''
        return zip_file_path

    def get_file_mtime(self, file_path):
        ret = 0
        try:
            ret = os.path.getmtime(file_path)
        except Exception as e:
            self.l.error("Cannot get mtime of file: [{} {}]".format(file_path, e))
        return ret

    def clear_dir(self, dir_path, file_ext="json", age_in_days=7):
        self.l.debug("Cleaning directory: [{}] | days: [{}]".format(dir_path, age_in_days))
        purge_cnt = 0
        age_in_seconds = int(age_in_days) * 86400 * 1000
        cut_off_epoch = self._get_ts() - age_in_seconds
        try:
            for f in os.listdir(dir_path):
                if f.endswith(".{}".format(file_ext)):
                    f_path = "{}/{}".format(dir_path, f)
                    f_mtime = os.path.getmtime(f_path) * 1000
                    if f_mtime < cut_off_epoch:
                        self.l.info(
                            "Local file age greater than days old: [{}] | deleting: [{}]".format(age_in_days, f_path))
                        os.remove(f_path)
                        purge_cnt += 1
        except Exception as e:
            self.l.error("Problem cleaning directory: [{}] [{}]".format(dir_path, e))
        return purge_cnt

    def send_json_to_sensor(self, data={}):
        try:
            if self.httpjson_forwarder_url and data:
                url = "{}".format(self.httpjson_forwarder_url)
                headers = {"Content-Type": "application/json"}
                if self.httpjson_forwarder_onprem:
                    data = {'httpjson': data}
                r = requests.post(url=url, headers=headers, json=data, verify=False)
                if 200 <= r.status_code <= 299:
                    # self.l.info("Successfully posted to httpjson forwarder: [{}]".format(url))
                    pass
                else:
                    self.l.error("Problem with httpjson forwarder: [{}]".format(url))
        except Exception as e:
            self.l.error("Problem with send_json_to_sensor: [{}]".format(e))

    def _get_auth_header(self):
        return_code = 0
        header_string = ''
        auth = base64.b64encode(bytes(self.stellar_fb_user + ":" + self.stellar_fb_api_key, "utf-8")).decode("utf-8")
        if self.stellar_new_auth:
            ts = self._get_epoch()
            current_token = self.oauth.get('token', '')
            current_exp = int(self.oauth.get('exp', 0))
            if ts < current_exp and current_token:
                pass
            else:
                path = '/connect/api/v1/access_token'
                url = 'https://{}{}'.format(self.stellar_dp, path)
                headers = {
                    "Authorization": "Bearer {}".format(self.stellar_fb_api_key),
                }
                # r = self._request_post(headers=headers, path=path)
                try:
                    r = requests.post(url, verify=False, headers=headers, timeout=10)
                    return_code = r.status_code
                    if 200 <= r.status_code <= 299:
                        response = r.json()
                        current_token = response.get('access_token', '')
                        current_exp = int(response.get('exp', 0))
                        header_string = "Bearer {}".format(current_token)
                        self.oauth = {"token": current_token, "expires": current_exp}
                    else:
                        response = r.text
                        raise Exception("{}".format(response))
                except Exception as e:
                    self.l.error("Cannot get stellar access token (user api key): [{} {}]".format(return_code, e))
        elif self.stellar_saas:
            ts = self._get_epoch()
            current_token = self.oauth.get('token', '')
            current_exp = int(self.oauth.get('exp', 0))
            if ts < current_exp and current_token:
                pass
            else:
                path = '/connect/api/v1/access_token'
                url = 'https://{}{}'.format(self.stellar_dp, path)
                headers = {
                    "Authorization": "Basic {}".format(auth),
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                # r = self._request_post(headers=headers, path=path)
                try:
                    r = requests.post(url, verify=False, headers=headers, timeout=10)
                    return_code = r.status_code
                    if 200 <= r.status_code <= 299:
                        response = r.json()
                        current_token = response.get('access_token', '')
                        current_exp = int(response.get('exp', 0))
                        header_string = "Bearer {}".format(current_token)
                        self.oauth = {"token": current_token, "expires": current_exp}
                    else:
                        response = r.text
                        raise Exception("{}".format(response))
                except Exception as e:
                    self.l.error("Cannot get stellar access token: [{} {}]".format(return_code, e))
        else:
            header_string = "Basic {}".format(auth)

        return header_string

    def _request_get(self, path, headers=None, data=None):
        return_code = 500
        ret = {}
        if not headers:
            headers = self.headers
        return_code = 0
        try:
            url = 'https://{}{}'.format(self.stellar_dp, path)
            headers['Authorization'] = self._get_auth_header()
            if not headers['Authorization']:
                raise Exception("Authorization failed")
            r = requests.get(url, verify=False, headers=headers, data=data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                # TODO: handle pagination
            else:
                ret = {"data": {"error": r.text}}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform GET request: [{} {}]".format(return_code, e))

        return ret

    def _request_post(self, path, data={}, headers=None):
        return_code = 500
        ret = None
        if not headers:
            headers = self.headers
        try:
            if not self.stellar_fb_user or not self.stellar_fb_api_key:
                raise Exception("Cannot perform POST request due to stellar user or api key not configured")

            url = 'https://{}{}'.format(self.stellar_dp, path)
            headers['Authorization'] = self._get_auth_header()
            if not headers['Authorization']:
                raise Exception("Authorization failed")
            r = requests.post(url, verify=False, headers=headers, json=data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                if r.text:
                    ret = r.json()
            else:
                ret = {"data": {"error": r.text}}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform POST request: [{} {}]".format(return_code, e))

        return ret

    def _request_put(self, path, data={}, headers=None):
        return_code = 500
        ret = None
        if not headers:
            headers = self.headers
        try:
            if not self.stellar_fb_user or not self.stellar_fb_api_key:
                raise Exception("Cannot perform PUT request due to stellar user or api key not configured")

            url = 'https://{}{}'.format(self.stellar_dp, path)
            headers['Authorization'] = self._get_auth_header()
            if not headers['Authorization']:
                raise Exception("Authorization failed")
            r = requests.put(url, verify=False, headers=headers, json=data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
            else:
                ret = {"data": {"error": r.text}}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform PUT request: [{} {}]".format(return_code, e))

        return ret

    def _request_patch(self, path, data={}, headers=None):
        return_code = 500
        ret = None
        if not headers:
            headers = self.headers
        try:
            if not self.stellar_fb_user or not self.stellar_fb_api_key:
                raise Exception("Cannot perform PATCH request due to stellar user or api key not configured")

            url = 'https://{}{}'.format(self.stellar_dp, path)
            headers['Authorization'] = self._get_auth_header()
            if not headers['Authorization']:
                raise Exception("Authorization failed")
            r = requests.patch(url, verify=False, headers=headers, json=data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
            else:
                ret = {"data": {"error": r.text}}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform PATCH request: [{} {}]".format(return_code, e))

        return ret

    def _request_delete(self, path, data={}, headers=None):
        return_code = 500
        ret = None
        if not headers:
            headers = self.headers
        try:
            if not self.stellar_fb_user or not self.stellar_fb_api_key:
                raise Exception("Cannot perform DELETE request due to stellar user or api key not configured")

            url = 'https://{}{}'.format(self.stellar_dp, path)
            headers['Authorization'] = self._get_auth_header()
            if not headers['Authorization']:
                raise Exception("Authorization failed")
            r = requests.delete(url, verify=False, headers=headers, json=data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
            else:
                ret = {"data": {"error": r.text}}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform DELETE request: [{} {}]".format(return_code, e))

        return ret

    def _get_scroll_query(self, scroll_id):
        ret_query = json.dumps(
            {
                "scroll": "1m",
                "scroll_id": "{}".format(scroll_id)
            }
        )
        return ret_query

    def _get_ts(self):
        return int(time.time() * 1000)

    def _get_date(self):
        return datetime.now().strftime("%Y/%m/%d")

    def _get_epoch(self):
        return int(time.time())

    def get_script_path(self):
        return os.path.dirname(os.path.realpath(sys.argv[0]))

    def datestring_to_epoch(self, datestring, date_format="%Y-%m-%dT%H:%M:%S.%fZ"):
        utc_time = datetime.strptime(datestring, date_format)
        epoch_time = (utc_time - datetime(1970, 1, 1)).total_seconds()
        return epoch_time

    def epoch_to_datestring(self, epoch_time, date_format="%Y-%m-%d %H:%M:%S [%z %Z]"):
        ret = ''
        try:
            if len(str(int(epoch_time))) > 12:
                epoch_time = epoch_time / 1000
            dt_object = datetime.fromtimestamp(epoch_time).astimezone()
            ret = dt_object.strftime(date_format)
        except:
            pass
        return ret

class local_db():

    def __init__(self, dbname='stellar_speartip.db', ticket_table_name='tickets', optional_db_dir=None):
        """General Stellar SQLite Class for tracking case syncroniozation with remote ticketing systems.

        dbname -- name of the local db file
        ticket_table_name -- name of the ticket table within the local db
        """

        # set default data directory to current directory
        path_to_data = "{}".format(os.path.dirname(os.path.realpath(sys.argv[0])))
        if optional_db_dir:
            if str(optional_db_dir).startswith("/"):
                # absolute
                path_to_data = optional_db_dir
            else:
                # relative to current directory
                path_to_data = "{}/{}".format(os.path.dirname(os.path.realpath(sys.argv[0])), optional_db_dir)
        if not os.path.exists(path_to_data):
            raise Exception("Path to data does not exist: [{}]".format(path_to_data))
        db_path = "{}/{}".format(path_to_data, dbname)
        self.con = sl.connect(db_path)
        self.ticket_table_name = ticket_table_name
        self._create_ticket_table()

    def checktable(self):
        """ does the default table exist ? """
        # sql = 'select exists(select 1 from sqlite_master where type="table" and name="remote_ticket");'
        sql = 'select name from sqlite_master where type="table";'
        # sql = '.tables;'
        with self.con:
            cur = self.con.cursor()
            r = cur.execute(sql).fetchall()
            print(r)

    def put_ticket_linkage(self, stellar_case_id, stellar_case_number, remote_ticket_id, stellar_tenant_id='',
                           stellar_last_modified=None, remote_ticket_last_modified=None, state="new"):
        ts = int(time.time()) * 1000
        if not stellar_last_modified:
            stellar_last_modified = ts
        if not remote_ticket_last_modified:
            remote_ticket_last_modified = ts

        sql = """INSERT INTO {0}
        (stellar_case_id, stellar_case_number, remote_ticket_id, stellar_tenant_id, stellar_last_modified, remote_ticket_last_modified, state, ts)
        VALUES("{1}", {2}, "{3}", "{4}", {5}, {6}, "{7}", {8});""".format(
            self.ticket_table_name,
            stellar_case_id,
            stellar_case_number,
            remote_ticket_id,
            stellar_tenant_id,
            stellar_last_modified,
            remote_ticket_last_modified,
            state,
            ts)
        with self.con:
            cur = self.con.cursor()
            r = cur.execute(sql)

    def get_ticket_linkage(self, stellar_case_id=None, stellar_case_number=None, remote_ticket_id=None):
        ret = {}
        field = ''
        field_val = ''
        if stellar_case_id:
            field = "stellar_case_id"
            field_val = stellar_case_id
        elif stellar_case_number:
            field = "stellar_case_number"
            field_val = stellar_case_number
        elif remote_ticket_id:
            field = "remote_ticket_id"
            field_val = remote_ticket_id
        if field:
            sql = 'SELECT stellar_case_id, stellar_case_number, remote_ticket_id, remote_ticket_last_modified, state ' \
                  'FROM {} WHERE {} = "{}";'.format(self.ticket_table_name, field, field_val)
            with self.con:
                cur = self.con.cursor()
                r = cur.execute(sql).fetchone()
                if r:
                    stellar_case_id = r[0]
                    stellar_case_number = r[1]
                    remote_ticket_id = r[2]
                    remote_ticket_last_modifed = r[3]
                    state = r[4]
                    ret = {"stellar_case_id": stellar_case_id,
                           "stellar_case_number": stellar_case_number,
                           "remote_ticket_id": remote_ticket_id,
                           "remote_ticket_last_modified": remote_ticket_last_modifed,
                           "state": state}
        return ret

    def get_open_tickets(self):
        ret = []
        sql = 'SELECT stellar_case_id, stellar_case_number, remote_ticket_id, state, remote_ticket_last_modified, stellar_last_modified ' \
              'FROM {} WHERE state != "closed" ORDER BY ts asc;'.format(self.ticket_table_name)
        with self.con:
            cur = self.con.cursor()
            records = cur.execute(sql).fetchall()
            if records:
                for r in records:
                    stellar_case_id = r[0]
                    stellar_case_number = r[1]
                    remote_ticket_id = r[2]
                    state = r[3]
                    remote_ticket_last_modified = r[4]
                    stellar_last_modified = r[5]
                    ret.append({"stellar_case_id": stellar_case_id, "stellar_case_number": stellar_case_number,
                                "remote_ticket_id": remote_ticket_id, "state": state,
                                "remote_ticket_last_modified": remote_ticket_last_modified,
                                "stellar_last_modified": stellar_last_modified})
        return ret

    def close_ticket_linkage(self, stellar_case_id):
        ts = int(time.time()) * 1000
        sql = 'UPDATE {} SET state = "closed", ts = {} WHERE stellar_case_id = "{}"'.format(self.ticket_table_name, ts,
                                                                                            stellar_case_id)
        with self.con:
            cur = self.con.cursor()
            r = cur.execute(sql)

    def update_remote_ticket_timestamp(self, stellar_case_id, rt_ticket_ts=None):
        ts = int(time.time()) * 1000
        if not rt_ticket_ts:
            rt_ticket_ts = ts
        sql = 'UPDATE {} SET remote_ticket_last_modified = {}, ts = {} WHERE stellar_case_id = "{}"'.format(
            self.ticket_table_name, rt_ticket_ts, ts, stellar_case_id)
        with self.con:
            cur = self.con.cursor()
            r = cur.execute(sql)

    def _create_ticket_table(self):
        sql = """CREATE TABLE IF NOT EXISTS {} (
	        stellar_case_id TEXT,
	        stellar_case_number INTEGER,
	        stellar_tenant_id TEXT,
	        stellar_last_modified INTEGER,
	        remote_ticket_id TEXT,
	        remote_ticket_last_modified INTEGER,
	        state TEXT,
	        ts INTEGER);
            """.format(self.ticket_table_name)
        with self.con:
            cur = self.con.cursor()
            r = cur.execute(sql)
