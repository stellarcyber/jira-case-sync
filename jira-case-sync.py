#!/usr/bin/env python3

__version__ = '20251027.001'

'''
    version history
        20240430.000    initial build
        20240613.000    added jira side checks for status and comments - update stellar side accordingly
        20240820.000    updated to use latest (>5.1.1) case -> alert APIs
        20240823.000    added testmode option to skip checking on jira resolved issues
        20240826.000    added support for tenant filter list
        20240828.000    fixed minor issue with call to jira datestring to epoch
        20240828.001    added option for adding jira assignee to stellar case comments
        20241003.000    added ability to update stellar severity based on jira priority
        20250307.000    added sleep timer calculation to account for the time it tool to interate through the main loop
                        fixed jira URL to point to browser based URL rather than API to ticket
        20250826.000    added support for per tenant jira key mapping
        20250908.000    moved to LOGGING_UTIL for webhook log reception
        20250915.000    added stellar to jira sync for comments and case updates (score / new alerts)
        20251016.000    added config item to set the stellar case status after the initial sync with jira (was "In Progress")
        20251020.000    added functionality to support sync'ing stellar case status over to jira status
        20251022.001    added extra debugging to assist with understanding stellar -> jira sync decisions
        20251022.002    other logic adjustments for case resolution clarity
        20251027.000    rearchitected the way that existing jira tickets are processed; using JQL and timestamp
        20251027.001    cleanup

'''

__usage__ = '''
Enable sync between stellar cases and JIRA issues
'''

import argparse
import yaml
import STELLAR_UTIL
from JIRA import StellarJIRA
from time import time, sleep
import os
import traceback
import json
from LOGGER_UTIL import logger_util

parser = argparse.ArgumentParser(usage=__usage__)
parser.add_argument("-c", "--config", help='use yaml config (default: config.yaml)', dest='yaml_config',
                    default='config.yaml')
parser.add_argument('-l', '--log-file', help='Write stdout to logfile', dest='logfile', default='')
parser.add_argument('-p', '--persistent-volume',
                    help='Path to persistent volume that contains the in-sync database and checkpoint timestamp files. \
                     If empty, then current directory is used and if not prepended with "/", relative paths are assumed. \
                     (NOTE: db and checkpoint files are created automatically) ', dest='data_volume', default='')
parser.add_argument('-d', '--debug', help='Turn on debug/verbose logging', dest='verbose', action='store_true')
parser.add_argument('--test-mode', help=argparse.SUPPRESS, dest='TEST_MODE', default=False, action='store_true')
args = parser.parse_args()
l = logger_util(args)

def format_case_description(tenant_name, case_summary, case_score, case_observables, alerts, stellar_url):
    case_description = "*Tenant:* {}\n\n".format(tenant_name)
    case_description += "*Score:* {}\n\n".format(case_score)
    case_description += "*Summary:*\n{}\n\n".format(case_summary)
    case_description += "*Observables:*\n{}\n\n".format(case_observables)
    case_description += "*Security Alerts:*\n{}\n\n".format(alerts)
    case_description += "*Link to Stellar Case:* {}".format(stellar_url)
    return case_description


def load_tenants(SU, key_field_name=None):
    tenant_project_key_map = {}
    if key_field_name:
        all_tenants = SU.get_tenants()
        if not all_tenants:
            raise Exception('Problem getting list of tenants for project key mapping - cannot continue')
        for tenant in all_tenants:
            tenant_id = tenant.get('cust_id')
            if not tenant_id:
                continue
            jira_project_key = str(tenant.get(key_field_name, ''))
            tenant_project_key_map[tenant_id] = jira_project_key

    return tenant_project_key_map


def get_env():
    env_config = {}
    jira_url = os.environ.get("JIRA_URL", '')
    jira_user = os.environ.get("JIRA_USER", '')
    jira_secret = os.getenv("JIRA_SECRET", '')
    jira_basic_auth = int(os.getenv("JIRA_BASIC_AUTH", 1))
    stellar_dp = os.getenv("STELLAR_DP", '')
    stellar_user = os.getenv("STELLAR_USER", '')
    stellar_api_key = os.getenv("STELLAR_API_KEY", '')
    stellar_rbac_user = int(os.getenv("STELLAR_RBAC_USER", 0))
    stellar_saas = int(os.getenv('STELLAR_SAAS', 0))
    webhook_ingest_url = os.getenv('WEBHOOK_INGEST_URL', '')
    webhook_ingest_key = os.getenv('WEBHOOK_INGEST_KEY', '')
    if (jira_user and jira_secret and stellar_user and stellar_api_key):
        env_config['jira_url'] = jira_url
        env_config['jira_user'] = jira_user
        env_config['jira_secret'] = jira_secret
        env_config['jira_basic_auth'] = jira_basic_auth
        env_config['stellar_dp'] = stellar_dp
        env_config['stellar_user'] = stellar_user
        env_config['stellar_api_key'] = stellar_api_key
        env_config['stellar_new_rbac_user_auth'] = stellar_rbac_user
        env_config['stellar_saas'] = stellar_saas
        env_config['webhook_ingest_url'] = webhook_ingest_url
        env_config['webhook_ingest_key'] = webhook_ingest_key
    else:
        raise Exception("Missing environmental variables for API keys")
    return env_config


if __name__ == "__main__":

    try:
        with open(args.yaml_config, 'r') as config_file:
            config = yaml.safe_load(config_file)
            config.update(get_env())
            l.configure(config)

        POLL_INTERVAL = int(config.get('stellar_poll_interval', 5)) * 60
        TENANT_FILTER = config.get('tenant_filter', [])

        JIRA_COMMENT_SYNC = config.get('sync_jira_comments', False)
        JIRA_ASSIGNEE_UPDATE_AS_COMMENT = config.get('add_jira_assignee_to_comment', False)
        JIRA_PRIORITY_UPDATE = config.get('sync_jira_priority', False)
        JIRA_SYNC_STATE_RESOLVED = config.get('sync_jira_state_resolved', True)
        JIRA_SYNC_STATE_INPROGRESS = config.get('sync_jira_state_inprogress', False)
        JIRA_SYNC_STATE_REOPENED = config.get('sync_jira_state_reopen', False)
        JIRA_PRIORITY_MAP = config.get('jira_priority_map', {"Highest": "Critical", "High": "High", "Medium": "Medium", "Low": "Low", "Lowest": "Low"})

        STELLAR_SYNC_COMMENTS = config.get('sync_stellar_comments', False)
        STELLAR_SYNC_CASE_UPDATES = config.get('sync_stellar_case_updates', False)
        STELLAR_SYNC_CASE_STATUS_RESOLVED = config.get('sync_stellar_status_resolved', '')
        STELLAR_SYNC_CASE_STATUS_REOPENED = config.get('sync_stellar_status_reopened', '')
        STELLAR_SYNC_CASE_STATUS_INPROGRESS = config.get('sync_stellar_status_inprogress', '')
        STELLAR_SYNC_CASE_ASSIGNEE = config.get('sync_stellar_assignee_to_jira_comment', False)

        STELLAR_CASE_STATUS_ON_SYNC = config.get('stellar_case_status_upon_initial_sync', '')

        STELLAR_CHECKPOINT_FILENAME = "stellar_checkpoint"
        JIRA_CHECKPOINT_FILENAME = "jira_checkpoint"

        JIRA = StellarJIRA(logger=l, config=config)
        SU = STELLAR_UTIL.STELLAR_UTIL(logger=l, config=config, optional_data_path=args.data_volume)
        LDB = STELLAR_UTIL.local_db(ticket_table_name='jira_tickets', optional_db_dir=args.data_volume)

        ''' new functionality - per tenant jira project key mapping - 2025/08/26 '''
        _JIRA_PROJECT_KEY_FIELD_ = config.get('per_tenant_project_key_field', '')
        if _JIRA_PROJECT_KEY_FIELD_ and _JIRA_PROJECT_KEY_FIELD_ not in ['address', 'contact']:
            _JIRA_PROJECT_KEY_FIELD_ = ''
            raise Exception("The config item: per_tenant_project_key_field does not contain a valid string. Must be one of [address, contact]")

        while True:

            ts_start_of_loop = time()

            '''                                     '''
            '''     important stuff to do first     '''
            '''                                     '''

            ''' if this returns as an empty dict, the jira project key will default to the one defined in the config'''
            project_key_map = load_tenants(SU, _JIRA_PROJECT_KEY_FIELD_)

            ''' if using the servicedesk app, these values are necessary - else an empty call that does nothing'''
            JIRA.get_service_desk_ids()

            '''                                                             '''
            ''' get all ACTIVE SYNC jira -> stellar cases and find changes  '''
            '''                                                             '''
            NEW_CHECKPOINT_TS = int(time() * 1000)
            JIRA_CHECKPOINT_TS = int(SU.checkpoint_read(filepath=JIRA_CHECKPOINT_FILENAME))
            jira_issues = JIRA.get_issues(since_ts=JIRA_CHECKPOINT_TS)
            for jira_issue in jira_issues:
                if args.TEST_MODE:
                    break
                jira_issue_key = jira_issue.get('key', '')
                jira_issue_updated_str = jira_issue.get('fields', {}).get('updated', '')
                jira_issue_updated_ts = JIRA.jira_datestring_to_epoch(jira_issue_updated_str)

                """ if ticket linkage exists, this is an existing sync """
                open_ticket = LDB.get_ticket_linkage(remote_ticket_id=jira_issue_key)
                if open_ticket:
                    l.debug("Found an updated jira issue: [{}] [last updated: {}]".format(jira_issue_key, jira_issue_updated_str))
                    rt_ticket_number = open_ticket.get('remote_ticket_id', '')
                    rt_ticket_last_modified = open_ticket.get('remote_ticket_last_modified', '')
                    stellar_case_id = open_ticket.get('stellar_case_id', '')
                    stellar_case_number = open_ticket.get('stellar_case_number', '')

                    ''' update comments back to stellar '''
                    if JIRA_COMMENT_SYNC:
                        """ check the comment timestamps """
                        l.debug("Checking for new comments: [{}]".format(jira_issue_key))
                        jira_issue_comments = JIRA.get_comments(issue_id=jira_issue_key)
                        if jira_issue_comments:
                            for jira_comment in jira_issue_comments:
                                comment_updated_str = jira_comment.get('updated', '')
                                if comment_updated_str:
                                    comment_updated_ts = JIRA.jira_datestring_to_epoch(comment_updated_str)
                                    if comment_updated_ts > rt_ticket_last_modified:
                                        comment_body = jira_comment.get('body', '')
                                        comment_author = jira_comment.get('updateAuthor', {}).get('displayName', '')
                                        comment_str = "JIRA issue: {} updated by: {} comment: {}".format(rt_ticket_number, comment_author, comment_body)
                                        l.info("JIRA issue: [{}] | Stellar case: [{}] - adding comment: [{}: {}]".format(rt_ticket_number, stellar_case_number, comment_author, comment_updated_str))
                                        SU.update_stellar_case_comment(case_id=stellar_case_id, case_comment=comment_str)

                    ''' update assignee '''
                    if JIRA_ASSIGNEE_UPDATE_AS_COMMENT:
                        l.debug("Checking for new assignee: [{}]".format(jira_issue_key))
                        latest_assignee = ''
                        if jira_issue.get('fields', {}).get('assignee', {}):
                            latest_assignee_name = jira_issue.get('fields', {}).get('assignee', {}).get('displayName', '')
                            latest_assignee_email = jira_issue.get('fields', {}).get('assignee', {}).get('emailAddress', '')
                            latest_assignee = "Jira issue assigned to: {} ({})".format(latest_assignee_name, latest_assignee_email)
                        else:
                            latest_assignee = "Jira issue remains unassigned"

                        l.info("JIRA issue: [{}] | Stellar case: [{}] - updating comment with jira assignee: [{}]".format(rt_ticket_number, stellar_case_number, latest_assignee))
                        SU.update_stellar_case_comment(case_id=stellar_case_id, case_comment=latest_assignee)

                    ''' sync jira priority back to stellar case '''
                    if JIRA_PRIORITY_UPDATE:
                        l.debug("Syncing priority: [{}]".format(jira_issue_key))
                        if jira_issue.get('fields', {}).get('priority', {}):
                            jira_priority = jira_issue.get('fields', {}).get('priority', {}).get('name', "")
                            if jira_priority in JIRA_PRIORITY_MAP:
                                stellar_severity = JIRA_PRIORITY_MAP[jira_priority]
                                l.info("JIRA issue: [{}] | Stellar case: [{}] - updating case severity: [{}]".format(rt_ticket_number, stellar_case_number, stellar_severity))
                                SU.update_stellar_case_severity(case_id=stellar_case_id, case_severity=stellar_severity)

                    ''' sync jira status reopened and/or in progress '''
                    l.debug("Checking status change")
                    jira_issue_status = jira_issue.get('fields', {}).get('status', {}).get('name', '')
                    if JIRA_SYNC_STATE_REOPENED and jira_issue_status == "Reopened":
                        SU.update_stellar_case(case_id=stellar_case_id, case_status="New", update_tag=False)
                        l.info("JIRA issue: [{}] | Stellar case: [{}] - updating case status to: [{}]".format(rt_ticket_number, stellar_case_number, "NEW"))
                    elif JIRA_SYNC_STATE_INPROGRESS and jira_issue_status == "In Progress":
                        SU.update_stellar_case(case_id=stellar_case_id, case_status="In Progress", update_tag=False)
                        l.info("JIRA issue: [{}] | Stellar case: [{}] - updating case status to: [{}]".format(rt_ticket_number, stellar_case_number, "In Progress"))

                    ''' update local tracking db with timestamp of jira issue'''
                    LDB.update_remote_ticket_timestamp(stellar_case_id=stellar_case_id, rt_ticket_ts=jira_issue_updated_ts, state="sync")

                    ''' resolved issues will have something populated in the 'resolved' section of the dataset '''
                    ''' this state ignores the timestamps associated with jira issue modification'''
                    if JIRA_SYNC_STATE_RESOLVED:
                        jira_resolution = jira_issue.get('fields', {}).get('resolution', {})
                        if jira_resolution:
                            jira_resolution_description = jira_resolution.get('description', '')
                            jira_resolution_name = jira_resolution.get('name', '')
                            l.info("JIRA issue is in resolved state: [{}] - marking stellar case closed: [{}: {}]".format(rt_ticket_number, stellar_case_number, stellar_case_id))
                            # SU.update_stellar_case(case_id=stellar_case_id, case_status="Resolved", case_comment=jira_resolution_description, update_tag=False, )
                            SU.resolve_stellar_case(case_id=stellar_case_id, resolution=jira_resolution_name)
                            LDB.close_ticket_linkage(stellar_case_id=stellar_case_id)


            '''                                             '''
            ''' get all STELLAR cases since last checkpoint '''
            '''                                             '''

            ''' manage checkpoint '''
            NEW_CHECKPOINT_TS = int(time() * 1000)
            CHECKPOINT_TS = int(SU.checkpoint_read(filepath=STELLAR_CHECKPOINT_FILENAME))
            cases = SU.get_stellar_cases(from_ts=CHECKPOINT_TS, use_modified_at=True)
            # cases = SU.get_stellar_cases(from_ts=1721930052690)
            # cases = {"cases": [SU.get_stellar_case_by_id(case_id="68ff2749332356d2debdd1ec")]}
            for case in cases.get('cases', {}):
                stellar_case_id = case.get("_id")
                stellar_case_number = case.get('ticket_id')
                stellar_case_modified_ts = case.get('modified_at', 0)
                stellar_case_last_modified_by = case.get('modified_by_name', '')
                stellar_case_status = case.get('status', '')

                """ if ticket linkage exists, this is an existing sync """
                ticket_linkage = LDB.get_ticket_linkage(stellar_case_id=stellar_case_id)
                if ticket_linkage:
                    rt_ticket_number = ticket_linkage.get('remote_ticket_id', '')
                    rt_ticket_last_modified = ticket_linkage.get('remote_ticket_last_modified', 0)
                    stellar_case_activities = SU.get_case_activities(case_id=stellar_case_id)
                    sync_state = ticket_linkage.get('state', '')

                    if sync_state == 'closed':
                        ''' see if there is a status change - might need to reopen '''
                        if stellar_case_status in ['Resolved', 'Cancelled']:
                            ''' skip if resolved - if not, reopen below if optioned '''
                            continue

                    if stellar_case_modified_ts > rt_ticket_last_modified:

                        # ''' if this case was last modified by the API user, most likely can skip to prevent recursive updates '''
                        # if stellar_case_last_modified_by == SU.stellar_fb_user:
                        #     l.info("Stellar case last modified by API user - skipping to prevent recursive updates")
                        #     continue

                        ''' update comments if optioned '''
                        if STELLAR_SYNC_COMMENTS:
                            stellar_case_comments = SU.get_case_comments(case_id=stellar_case_id)
                            for stellar_case_comment in stellar_case_comments:
                                comment_ts = int(stellar_case_comment.get('created_at', 0))
                                comment_text = stellar_case_comment.get('comment', '')
                                comment_user = stellar_case_comment.get('user')
                                if comment_ts > rt_ticket_last_modified:
                                    note_text = "*Stellar case comment added:*\n\n{}".format(comment_text)
                                    JIRA.add_comment( issue_id=rt_ticket_number, comment_body=note_text)
                                    LDB.update_remote_ticket_timestamp(stellar_case_id=stellar_case_id, rt_ticket_ts=comment_ts)

                        ''' update stellar case score  '''
                        if STELLAR_SYNC_CASE_UPDATES:
                            stellar_case_score = case.get('score', 0)
                            latest_case_score = SU.get_latest_case_score(stellar_case_id)
                            latest_case_score_ts = latest_case_score.get('timestamp', 0)
                            if latest_case_score_ts >= rt_ticket_last_modified:

                                ''' the case score has been updated since last checked '''
                                l.debug(
                                    "Stellar case score update - updating priority and adding note: Stellar Case ID: [{}] | Ticket Number: [{}] | JIRA id: [{}]".format(
                                        stellar_case_id, stellar_case_number, rt_ticket_number))

                                ''' grab the reason the score was change - if the reason exists '''
                                score_change_reasons = latest_case_score.get('reasons', [])
                                if score_change_reasons:
                                    score_change_reason = score_change_reasons[0].get('reason', '')

                                ''' populate and format the final note to be added '''
                                note_text = "*Stellar Case Score has change to: {}*\n\nReason: {}".format(
                                    stellar_case_score, score_change_reason)

                                ''' add the note and update the score '''
                                JIRA.add_comment(issue_id=rt_ticket_number, comment_body=note_text)

                                ''' update the local db - using the case score timestamp to prevent the me request from recursive updates back to stellar '''
                                LDB.update_remote_ticket_timestamp(stellar_case_id=stellar_case_id, rt_ticket_ts=latest_case_score_ts)

                        if STELLAR_SYNC_CASE_ASSIGNEE:
                            for case_activity in stellar_case_activities:
                                case_activity_field = case_activity.get('field', '')
                                case_activity_ts = case_activity.get('timestamp', 0)
                                if case_activity_field == "assignee" and case_activity_ts > rt_ticket_last_modified:
                                    new_assignee = case.get('assignee_name', '')
                                    if new_assignee:
                                        note_text = "*Stellar case assignment:*\n\n{}".format(new_assignee)
                                        JIRA.add_comment(issue_id=rt_ticket_number, comment_body=note_text)
                                        l.debug(
                                            "Stellar case updated with assignee - adding jira note: Stellar Case ID: [{}] | JIRA id: [{}] | Assignee: [{}]".format(
                                                stellar_case_id, rt_ticket_number, new_assignee))
                                        LDB.update_remote_ticket_timestamp(stellar_case_id=stellar_case_id,
                                                                           rt_ticket_ts=stellar_case_modified_ts)
                                        ''' only do one otherwise older entries could clobber newer ones '''
                                        break

                        ''' status change - new or inprogress '''
                        if STELLAR_SYNC_CASE_STATUS_REOPENED or STELLAR_SYNC_CASE_STATUS_INPROGRESS:
                            for case_activity in stellar_case_activities:
                                case_activity_field = case_activity.get('field', '')
                                case_activity_ts = case_activity.get('timestamp', 0)
                                if case_activity_field == "status" and case_activity_ts > rt_ticket_last_modified:
                                    new_status = case_activity.get('to', '')
                                    case_status = case.get('status', '')
                                    if new_status == case_status and new_status == "New":
                                        l.debug("Setting jira status: {}".format(STELLAR_SYNC_CASE_STATUS_REOPENED))
                                        JIRA.update_issue_state(issue_id=rt_ticket_number,
                                                                state_name=STELLAR_SYNC_CASE_STATUS_REOPENED)
                                        LDB.update_remote_ticket_timestamp(stellar_case_id=stellar_case_id,
                                                                           rt_ticket_ts=stellar_case_modified_ts,
                                                                           state="sync")
                                        break
                                    elif new_status == case_status and new_status in ["In Progress", "Escalated"]:
                                        l.debug("Setting jira status: {}".format(STELLAR_SYNC_CASE_STATUS_INPROGRESS))
                                        JIRA.update_issue_state(issue_id=rt_ticket_number,
                                                                state_name=STELLAR_SYNC_CASE_STATUS_INPROGRESS)
                                        LDB.update_remote_ticket_timestamp(stellar_case_id=stellar_case_id,
                                                                           rt_ticket_ts=stellar_case_modified_ts,
                                                                           state="sync")
                                        break

                    else:
                        l.debug("Stellar case modified but earlier then last ticket update: sc mod: {} | last sync mod: {}".format(stellar_case_modified_ts, rt_ticket_last_modified))

                    ''' if in resolved state, ignore timestamp comparison '''
                    if STELLAR_SYNC_CASE_STATUS_RESOLVED:
                        if stellar_case_status == "Resolved":
                            case_resolution = case.get('resolution', '')
                            l.info("Stellar case found in a resolved state. Resolving Jira issue: [case: {}] [jira: {}] [{}/{}]".format(stellar_case_id, rt_ticket_number, STELLAR_SYNC_CASE_STATUS_RESOLVED, case_resolution))
                            JIRA.resolve_issue(issue_id=rt_ticket_number, resolution_name=STELLAR_SYNC_CASE_STATUS_RESOLVED, resolution_type=case_resolution)
                            LDB.close_ticket_linkage(stellar_case_id=stellar_case_id)
                        elif stellar_case_status == "Canceled":
                            l.info("Stellar case found in a canceled state. Resolving Jira issue: [case: {}] [jira: {}] [{}/{}]".format(stellar_case_id, rt_ticket_number, STELLAR_SYNC_CASE_STATUS_RESOLVED,))
                            JIRA.resolve_issue(issue_id=rt_ticket_number,
                                               resolution_name=STELLAR_SYNC_CASE_STATUS_RESOLVED,
                                               resolution_type=case_resolution)
                            LDB.close_ticket_linkage(stellar_case_id=stellar_case_id)
                        else:
                            l.debug("Stellar case not found in resolved or canceled state: [{}]".format(stellar_case_id))

                else:

                    '''                                                                                         '''
                    ''' this is a new instance - create new jira ticket and insert linkage into local database  '''
                    '''                                                                                         '''
                    stellar_tenant_id = case.get('cust_id', '')
                    stellar_tenant_name = case.get('tenant_name', '')

                    ''' added 20240826.000 support tenant filter '''
                    if TENANT_FILTER and not stellar_tenant_name in TENANT_FILTER:
                        l.info("Case [{}: {}] for tenant: [{}] does not match tenant filter and will be skipped".format(stellar_case_number, case_name, stellar_tenant_name))
                        continue

                    ''' update 20250826.000 - dynamic jira project key based on tenant definition (if optioned) '''
                    if project_key_map:
                        jira_project_key = project_key_map.get(stellar_tenant_id, '')
                        if jira_project_key:
                            ''' set the new project key '''
                            JIRA.project_key = jira_project_key
                        else:
                            ''' skip if this tenant does not have a project key defined within their tenant '''
                            l.info("Skipping case - No jira project key defined for tenant: [{}]".format(stellar_tenant_name))
                            continue

                    case_name = case.get('name', '')
                    case_summary = SU.get_case_summary(case_id=stellar_case_id)
                    case_observables = SU.get_case_observables(case_id=stellar_case_id)
                    case_observables = JIRA.json2jiraformating(case_observables)
                    case_score = case.get('score', 1)
                    case_last_modified = case.get('modified_at', 0)
                    l.info("Processing stellar case: [tenant: {} | case: {} | jira_project_key: {}]".format(stellar_tenant_name, stellar_case_id, JIRA.project_key))

                    ''' update 20240820.000 - using newer case alert api '''
                    event_names = JIRA.list2jiraformating(SU.get_case_alerts(stellar_case_id, return_only_alert_names=True))
                    stellar_url = SU.make_stellar_case_url(stellar_case_id)
                    case_description = format_case_description(stellar_tenant_name, case_summary, case_score, case_observables, event_names, stellar_url)

                    ''' CREATE JIRA TICKET '''
                    jira_return = JIRA.create_issue(summary=case_name, description=case_description, case_score=case_score, label=stellar_tenant_name)
                    jira_id = jira_return.get('id', '')
                    jira_key = jira_return.get('key', '')
                    ''' updated 20250307.000 '''
                    jira_url = JIRA.get_jira_issue_url(jira_key)
                    if jira_id and jira_key and jira_url:
                        LDB.put_ticket_linkage(stellar_case_id=stellar_case_id, stellar_case_number=stellar_case_number, remote_ticket_id=jira_key)
                        stellar_case_comment = "Jira issue created: id: [{}] | key: [{}] | url: [{}]".format(jira_id, jira_key, jira_url)
                        l.info(stellar_case_comment)
                        SU.update_stellar_case (case_id=stellar_case_id, case_comment=stellar_case_comment, case_status=STELLAR_CASE_STATUS_ON_SYNC)

                        ''' check for assignee '''
                        new_assignee = case.get('assignee_name', '')
                        if new_assignee:
                            note_text = "*Stellar case assignment:*\n\n{}".format(new_assignee)
                            JIRA.add_comment(issue_id=jira_key, comment_body=note_text)

                    else:
                        l.error("Problem creating JIRA issue - no jira ID or KEY returned")

            SU.checkpoint_write(filepath=JIRA_CHECKPOINT_FILENAME, val=NEW_CHECKPOINT_TS)

            ''' for testing - bail after first run '''
            if args.TEST_MODE:
                exit(0)

            SU.checkpoint_write(filepath=STELLAR_CHECKPOINT_FILENAME, val=NEW_CHECKPOINT_TS)
            ts_loop_duration = time() - ts_start_of_loop
            if POLL_INTERVAL > ts_loop_duration:
                ts_sleep_time = POLL_INTERVAL - ts_loop_duration
                l.info("Process loop duration took {}s - sleeping: {}s".format(ts_loop_duration, ts_sleep_time))
                sleep(ts_sleep_time)
            else:
                l.warning("Process loop duration took longer than sleep time - staying awake to catch up")

    except Exception as e:
        l.critical("Fatal Error - {}".format(traceback.format_exc()))
        exit(1)

