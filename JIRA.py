__version__ = '20251120.000'

'''
    Provides methods to call JIRA API for issue creation and update

    version:    20240430.000    initial 
                20240823.000    fixed jira_datestring_to_epoch
                20240828.000    fixed get_issue errors when jira non-response
                                added better error handling for datetime conversion in jira_datestring_to_epoch
                20241003.000    added support for custom fields (for now just one custom field is supported - date field)
                20250307.000    added method to return the jira issue URL based on ticket key
                20250905.000    enhanced auth moded to support basic and bearer tokens
                20250916.000    added methods for getting or adding comments using the servicedeskapi and public tag
                20251020.000    added methods to support resolving a jira case with transitions and resolution types
                20251022.000    fixed small bug that ignored the configured summary prefix when using the service desk API
                20251027.000    added new method to get jira issues usiog JQL which allows for timestamp abd other filtering
                20251029.000    added new method to update jira issue with new priority
                20251120.000    updated both get_issues and get_service_desk_ids to handle pagination

'''

from datetime import datetime
import requests
import json
import base64
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class StellarJIRA:

    def __init__(self, logger, config={}):
        self.l = logger
        self.l.info('StellarJIRA version: [{}]'.format(__version__))


        self.jira_url = config.get('jira_url')
        jira_user = config.get('jira_user')
        jira_secret = config.get('jira_secret')
        jira_basic_auth = config.get('jira_basic_auth', 1)
        if jira_basic_auth:
            creds = "{}:{}".format(jira_user, jira_secret)
            encoded_creds = base64.b64encode(creds.encode("utf-8")).decode("ascii")
            auth_token = "Basic {}".format(encoded_creds)
        else:
            auth_token = "Bearer {}".format(jira_secret)
        self.headers = {'Content-Type': 'application/json',
                        'Accept': 'application/json;charset=utf-8',
                        'Authorization': "{}".format(auth_token)
                        }
        self.subject_prefix = config.get('subject_prefix', '')
        self.jira_project_key = config.get('jira_project_key', '')
        self.jira_issue_type = config.get('jira_issue_type', '')
        self.jira_assignee_accountid = config.get('jira_assignee_accountid', '')
        self.jira_custom_field = config.get('custom_field', "")
        self.sla = config.get('SLA', [])
        self.jira_comment_use_servicedesk_api = config.get('jira_comments_use_servicedesk_api', False)
        self.jira_comment_filter = config.get('jira_comments_filter', '')   # public, internal, empty (for all)
        self.jira_comments_as_public = config.get('sync_stellar_comments_as_public', True)
        self.jira_resolutions_map = config.get('stellar_case_resolutions', {})

    def get_version(self):
        return __version__

    @property
    def project_key(self):
        return self.jira_project_key

    @project_key.setter
    def project_key(self, value):
        self.jira_project_key = value

    def get_service_desk_ids(self):
        self.jira_servicedesk_ids = self._get_servicedesk_ids() if self.jira_comment_use_servicedesk_api else {}

    def _get_servicedesk_ids(self):
        ''' only needed if servicedeskapi is enabled '''
        sd_ids = {}
        return_code = 500

        try:
            start = 0
            limit = 50
            sd_last_page = False
            while not sd_last_page:
                path = "rest/servicedeskapi/servicedesk?limit={}&start={}".format(limit, start)
                url = "{}/{}".format(self.jira_url, path)
                r = requests.get(url=url, headers=self.headers)
                return_code = r.status_code
                if 200 <= r.status_code <= 299:
                    sd_all = r.json()
                    sd_cnt = sd_all.get('size', 0)
                    sd_last_page = sd_all.get('isLastPage', True)
                    sd_apps = sd_all.get('values', [])
                    for sd_app in sd_apps:
                        project_key = sd_app.get('projectKey', '')
                        sd_id = sd_app.get('id', 0)
                        rt_id = self._get_requesttype_id(servicedesk_id=sd_id)
                        sd_ids[project_key] = {"servicedesk_id": sd_id, "requesttype_id": rt_id}
                    start += sd_cnt
                else:
                    raise Exception("{}".format(r.text))
        except Exception as e:
            self.l.error("Cannot perform GET request for JIRA servicedesk ids: [{} {}]".format(return_code, e))
        self.l.info("Retrieved servicedesk ids: [{}]".format(len(sd_ids)))
        return sd_ids

    def _get_requesttype_id(self, servicedesk_id):
        ''' only needed if servicedeskapi is enabled '''
        rt_id = 0
        return_code = 500
        path = "rest/servicedeskapi/servicedesk/{}/requesttype".format(servicedesk_id)
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                request_types = r.json().get('values', [])
                for request_type in request_types:
                    rt_name = request_type.get('name', '')
                    if rt_name == self.jira_issue_type:
                        rt_id = request_type.get('id')
                        break
            else:
                raise Exception("{}".format(r.text))
        except Exception as e:
            self.l.error("Cannot perform GET request for servicedesk requesttypes: [{} {}]".format(return_code, e))
        return rt_id

    def get_projects(self):
        ret = {}
        return_code = 0
        path = "rest/api/2/project"
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform GET request: [{} {}]".format(return_code, e))

        return ret

    def get_issue_types(self, project_key):
        ret = {}
        path = "rest/api/2/issue/createmeta/{}/issuetypes".format(project_key)
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform GET request: [{} {}]".format(return_code, e))

        return ret

    def get_issue_fields(self, project_key, issue_id):
        ret = {}
        path = "rest/api/2/issue/createmeta/{}/issuetypes/{}".format(project_key, issue_id)
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform GET request: [{} {}]".format(return_code, e))

        return ret

    def get_issue(self, issue_id):
        ret = {}
        # path = "rest/servicedeskapi/request/{}".format(issue_id)
        path = "rest/api/2/issue/{}".format(issue_id)
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                # self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            msg = "Cannot perform get request for JIRA get issue: [{} {}]".format(return_code, e)
            ret = {"error": msg}
            self.l.error(msg)

        return ret

    def get_issues(self, since_ts):
        '''
        https://jira-stg.speartip.adaptavist.cloud/rest/api/2/search?jql=updated > -60m AND status = reopened AND issuekey IN ('DEME-363', 'DEME-364') AND issuetype = 'Security Event'
        https://developer.atlassian.com/server/jira/platform/rest/v11001/api-group-search/#api-api-2-search-get

        :param issue_id:
        :return:
        '''
        ret = []
        path = "rest/api/2/search?jql=updated >= {}".format(since_ts)
        url = "{}/{}".format(self.jira_url, path)
        if self.jira_issue_type:
            path += " AND issuetype = {}".format(self.jira_issue_type)
        # if issue_key_list:
        #     path += " AND issuekey IN ({})".format(issue_key_list)

        try:
            maxresults = 50
            r_cnt = 0
            while True:
                jql_url = "{}&maxResults={}&startAt={}".format(url, maxresults, r_cnt)
                r = requests.get(url=jql_url, headers=self.headers)
                return_code = r.status_code
                if 200 <= r.status_code <= 299:
                    r_json = r.json()
                    r_total = r_json.get('total', 0)
                    r_issues = r_json.get('issues', [])
                    r_cnt += len(r_issues)
                    ret.extend(r_issues)
                    if r_cnt >= r_total:
                        break
                    # self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
                else:
                    ret = {"error": r.text}
                    raise Exception("{}".format(r.text))

        except Exception as e:
            msg = "Cannot perform get request for JIRA get issue: [{} {}]".format(return_code, e)
            ret = {"error": msg}
            self.l.error(msg)

        return ret

    def create_issue(self, summary, description, case_score, label=''):
        ret = {}
        jira_summary = str('{}{}').format(self.subject_prefix, summary)
        if self.jira_comment_use_servicedesk_api:
            ret = self._create_request(summary=jira_summary, description=description, case_score=case_score, label=label)
        else:
            ret = self._create_issue(summary=jira_summary, description=description, case_score=case_score, label=label)
        return ret

    def _create_issue(self, summary, description, case_score, label=''):
        ret = {}
        path = "rest/api/2/issue"
        url = "{}/{}".format(self.jira_url, path)
        priority_name = self.get_ticket_priority(case_score)
        jira_data = {
            "fields": {
                "project":
                    {
                        "key": "{}".format(self.jira_project_key)
                    },
                "summary": "{}".format(summary),
                "description": "{}".format(description),
                "issuetype": {
                    "name": "{}".format(self.jira_issue_type)
                },
                "requestType": {
                    "name": "Security Event"
                },
                # "assignee": {
                #     "accountId": "{}".format(self.jira_assignee_accountid)
                # },
                "priority": {
                    "name": "{}".format(priority_name)
                },
                "labels": ["{}".format(label.replace(' ', '_'))]
            }
        }
        if self.jira_assignee_accountid:
            jira_data['fields']['assignee'] = self.jira_assignee_accountid
        if self.jira_custom_field:
            start_date = datetime.now().strftime("%Y-%m-%d")
            jira_data['fields'][self.jira_custom_field] = start_date

        try:
            r = requests.post(url=url, headers=self.headers, json=jira_data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                # self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform POST request for JIRA create_issue: [{} {}]".format(return_code, e))

        return ret

    def _create_request(self, summary, description, case_score, label=''):
        ''' this has to be done in 2 parts cause of the dumb jira app
            the initial call builds the request with the right serice desk id
            the second call uses the jira api to modify the rest of the fields that the servicedesk api can't
        '''
        r_ret = {"id": 0, "key": 0}
        return_code = 500
        jira_key = ''
        servicedesk_id = self.jira_servicedesk_ids.get(self.jira_project_key, {}).get('servicedesk_id')
        requesttype_id = self.jira_servicedesk_ids.get(self.jira_project_key, {}).get('requesttype_id')
        try:
            if servicedesk_id and requesttype_id:
                path = "rest/servicedeskapi/request"
                url = "{}/{}".format(self.jira_url, path)
                jira_data = {
                    "serviceDeskId": servicedesk_id,
                    "requestTypeId": requesttype_id,
                    "requestFieldValues": {
                        "summary": "{}".format(summary),
                        "description": "{}".format(description)
                    }
                }

                r = requests.post(url=url, headers=self.headers, json=jira_data)
                return_code = r.status_code
                if 200 <= r.status_code <= 299:
                    r_ret = r.json()
                    jira_key = r_ret.get('issueKey', '')
                    jira_id = r_ret.get('issueId', '')
                    ''' doctor the new record '''
                    r_ret['key'] = jira_key
                    r_ret['id'] = jira_id
                    self.l.info('Created servicedesk request: [{}]'.format(jira_key))
                else:
                    raise Exception("{}".format(r.text))

                if jira_key:
                    priority_name = self.get_ticket_priority(case_score)
                    jira_data = {
                        "fields": {
                            "priority": {"name": "{}".format(priority_name)},
                            "labels": ["{}".format(label.replace(' ', '_'))]
                        }
                    }
                    if self.jira_assignee_accountid:
                        jira_data['fields']['assignee'] = self.jira_assignee_accountid
                    if self.jira_custom_field:
                        start_date = datetime.now().strftime("%Y-%m-%d")
                        jira_data['fields'][self.jira_custom_field] = start_date

                    path = "rest/api/2/issue/{}".format(jira_key)
                    url = "{}/{}".format(self.jira_url, path)
                    r = requests.put(url=url, headers=self.headers, json=jira_data)
                    return_code = r.status_code
                    if 200 <= r.status_code <= 299:
                        pass
                    else:
                        raise Exception("Problem updating jira issue after servicedesk created request: [{}] [{}]".format(jira_key, r.text))
            else:
                raise Exception("Servicedesk ID or Request ID not defined for Jira Project Key: [{}] - cannot create request".format(self.jira_project_key))

        except Exception as e:
            self.l.error("Cannot perform POST request for JIRA create_request: [{} {}]".format(return_code, e))

        return r_ret

    def add_comment(self, issue_id, comment_body=''):
        ret = {}
        return_code = 500
        if self.jira_comment_use_servicedesk_api:
            path = "rest/servicedeskapi/request/{}/comment".format(issue_id)
        else:
            path = "rest/api/2/issue/{}/comment".format(issue_id)
        is_public = True if self.jira_comments_as_public else False
        url = "{}/{}".format(self.jira_url, path)
        jira_data = {
            "body": "{}".format(comment_body),
            "public": is_public
        }
        try:
            r = requests.post(url=url, headers=self.headers, json=jira_data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                # self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform POST request for JIRA add comment to issue: [{} {}]".format(return_code, e))

        return ret

    def get_comments(self, issue_id):
        ret = {}
        if self.jira_comment_use_servicedesk_api:
            ret = self._get_comments_servicedesk_api(issue_id)
        else:
            ret = self._get_comments_jira_api(issue_id)
        return ret

    def _get_comments_jira_api(self, issue_id):
        ret = {}
        path = "rest/api/2/issue/{}/comment".format(issue_id)
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json().get('values', []) if self.jira_comment_use_servicedesk_api else r.json().get('comments', [])
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))
        except Exception as e:
            self.l.error("Cannot perform GET request for JIRA get comments for issue: [{} {}]".format(return_code, e))
        return ret

    def _get_comment_by_id(self, issue_id, comment_id):
        ret = {}
        path = "rest/api/2/issue/{}/comment/{}".format(issue_id, comment_id)
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))
        except Exception as e:
            self.l.error("Cannot perform GET request for JIRA get comment for issue: [{} {}]".format(return_code, e))
        return ret

    def _get_comments_servicedesk_api(self, issue_id):
        ret = []
        path = "rest/servicedeskapi/request/{}/comment".format(issue_id)
        url = "{}/{}".format(self.jira_url, path)
        if self.jira_comment_filter == "public":
            url += "?internal=false"
        elif self.jira_comment_filter == "internal":
            url += "?public=false"
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                comments = r.json().get('values', [])
                for comment in comments:
                    c_id = comment.get('id', '')
                    ret.append(self._get_comment_by_id(issue_id=issue_id, comment_id=c_id))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))
        except Exception as e:
            self.l.error("Cannot perform GET request for JIRA get servicedesk comment for issue: [{} {}]".format(return_code, e))
        return ret

    def add_issue_attachment(self, issue_id, file_name, attachment_json):
        ''' add a json interflow record to the jira issue
            issue_id:   either the guid or key of an issue ('e.g. EX-39')
            file_name:  what you want the attachment to be named within the issue
            attachment_json:    can be the raw file contents OR can be a file handle returned from open(file, "rb")
            https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-attachments/#api-rest-api-3-issue-issueidorkey-attachments-post
        '''

        self.l.info("Uploading interflow as attachment: [{}] to jira ticket: [{}]".format(file_name, issue_id))
        return_code = 0
        ret = {}
        headers = {
            "Accept": "application/json",
            "X-Atlassian-Token": "no-check"
        }
        headers.update(self.headers)
        files = {"file": (file_name, attachment_json, "application-type")}
        path = "rest/api/2/issue/{}/attachments".format(issue_id)
        url = "{}/{}".format(self.jira_url, path)

        try:
            r = requests.post(url=url, headers=headers, files=files)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ret = r.json()
                # self.l.debug(json.dumps(ret, sort_keys=True, indent=4))
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform POST request for JIRA add_issue_attachment: [{} {}]".format(return_code, e))

        return ret

    def resolve_issue(self, issue_id, resolution_name, resolution_type=None):
        transitions = self._get_transitions(issue_id=issue_id)
        jira_resolution = ''
        return_code = 500
        if resolution_name in transitions:
            t_id = transitions[resolution_name]
            if self.jira_resolutions_map:
                if resolution_type and resolution_type in self.jira_resolutions_map:
                    jira_resolution = self.jira_resolutions_map[resolution_type]
                elif "Default" in self.jira_resolutions_map:
                    jira_resolution = self.jira_resolutions_map["Default"]
            if t_id:
                j_data = {"transition": {"id": t_id}}
                if jira_resolution:
                    j_data['fields'] = {"resolution": {"name": jira_resolution}}
                path = "rest/api/2/issue/{}/transitions".format(issue_id)
                url = "{}/{}".format(self.jira_url, path)
                try:
                    r = requests.post(url=url, headers=self.headers, json=j_data)
                    return_code = r.status_code
                    if 200 <= r.status_code <= 299:
                        ''' all good '''
                        pass
                    else:
                        ret = {"error": r.text}
                        raise Exception("{}".format(r.text))
                except Exception as e:
                    self.l.error("Cannot perform POST request for JIRA resolve issue: [{} {}]".format(return_code, e))
        else:
            self.l.error("Jira resolution name not found in transitions for this issue: [{}] [{}]".format(issue_id, resolution_name))

    def update_issue_state(self, issue_id, state_name):
        transitions = self._get_transitions(issue_id=issue_id)
        return_code = 500
        if state_name in transitions:
            t_id = transitions[state_name]
            if t_id:
                j_data = {"transition": {"id": t_id}}
                path = "rest/api/2/issue/{}/transitions".format(issue_id)
                url = "{}/{}".format(self.jira_url, path)
                try:
                    r = requests.post(url=url, headers=self.headers, json=j_data)
                    return_code = r.status_code
                    if 200 <= r.status_code <= 299:
                        ''' all good '''
                        pass
                    else:
                        ret = {"error": r.text}
                        raise Exception("{}".format(r.text))
                except Exception as e:
                    self.l.error("Cannot perform POST request for JIRA resolve issue: [{} {}]".format(return_code, e))
        else:
            self.l.error("Jira resolution name not found in transitions for this issue: [{}] [{}]".format(issue_id, state_name))

    def update_issue_priority(self, issue_id, new_priority):
        ret = {}
        return_code = 500
        path = "rest/api/2/issue/{}".format(issue_id)
        url = "{}/{}".format(self.jira_url, path)
        jira_data = {
            "fields": {
                 "priority": {
                    "name": "{}".format(new_priority)
                }
            }
        }
        try:
            r = requests.put(url=url, headers=self.headers, json=jira_data)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                ''' all good '''
                pass
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))

        except Exception as e:
            self.l.error("Cannot perform PUT request for JIRA update_issue_priority: [{} {}]".format(return_code, e))

        return ret


    def _get_transitions(self, issue_id):
        ret = {}
        path = "rest/api/2/issue/{}/transitions".format(issue_id)
        url = "{}/{}".format(self.jira_url, path)
        try:
            r = requests.get(url=url, headers=self.headers)
            return_code = r.status_code
            if 200 <= r.status_code <= 299:
                transitions = r.json().get('transitions', [])
                for transition in transitions:
                    t_id = transition.get('id')
                    t_name = transition.get('to', {}).get('name', '')
                    if t_id and t_name:
                        ret[t_name] = t_id
            else:
                ret = {"error": r.text}
                raise Exception("{}".format(r.text))
        except Exception as e:
            self.l.error("Cannot perform GET request for JIRA get_transitions for issue: [{} {}]".format(return_code, e))

        return ret

    def json2jiraformating(self, json_value: dict):
        """
        *ITEM*      makes bold
        * ITEM      is a first level bulleted string
        ** ITEM     is a second level and so forth
        """
        ob_str = ""
        for ob_lists in json_value:
            ob_str += "* {}\n".format(ob_lists)
            ob_list = json_value.get(ob_lists, [])
            for ob_item in ob_list:
                tmp_str = ''
                for k in ob_item:
                    tmp_str += "{}: {} | ".format(k, ob_item.get(k, ''))
                tmp_str = tmp_str.rstrip(' | ')
                ob_str += "** {}\n".format(tmp_str)
        return ob_str

    def list2jiraformating(self, list_of_items: list):
        """
        * ITEM      is a first level bulleted string
        """
        ob_str = ""
        for list_item in list_of_items:
            ob_str += "* {}\n".format(list_item)
        return ob_str

    def get_ticket_priority(self, case_score):
        try:
            event_score = float(case_score)
            ticket_priority_name = ''
            ticket_priority_id = 0
            sla = self.sla
            if sla:
                for ticket_priority_name in sla:
                    ticket_priority_id = sla[ticket_priority_name]['jira_priority']
                    if event_score >= sla[ticket_priority_name]['min']:
                        break
            self.l.info("Setting ticket priority: [{}: {}]".format(ticket_priority_id, ticket_priority_name))
        except:
            self.l.error("Problem with setting ticket priority")
        return (ticket_priority_name)

    def jira_datestring_to_epoch(self, datestring):
        # dformat = "%Y-%m-%dT%H:%M:%S.%f+0000"   # broken most of the time
        epoch_time = 0
        dformat = "%Y-%m-%dT%H:%M:%S.%f%z"
        try:
            epoch_time = int(datetime.strptime(datestring, dformat).timestamp()) * 1000
        except(ValueError) as e:
            self.l.error("Time conversion error: [{}]".format(e))
        return epoch_time

    def get_jira_issue_url(self, jira_issue_key):
        jira_issue_url = "{}/browse/{}".format(self.jira_url, jira_issue_key)
        return jira_issue_url


