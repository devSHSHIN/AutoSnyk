import json
import argparse

issue_cnt = 1
issues_data = []
long_log = []

def process_issues(issues_dict, to_ver_default, add_only_first=False):

    global issue_cnt
    for key, value in issues_dict.items():

        if value['issues']:
            first_issue = value['issues'][0]
            severity = first_issue['issueData']['severity'].capitalize()
           
            if severity in ['Critical', 'High']:
                issue_to_xlsx = {
                    "no": '',
                    "platform": '',
                    "cwe_name": first_issue['issueData']['title'],
                    "result": '',
                    "date": '',
                    "patch_result": '',
                    "severity": first_issue['issueData']['severity'].capitalize(),
                    "package": first_issue['pkgName'],
                    "now_ver": first_issue['pkgVersions'],
                    "to_ver": value.get('patchversion', to_ver_default),
                    "many": str(value['count'] - 1),
                    "plan": '',
                    "detail": '',
                    "patch_date": '',
                    "commit_no": ''
                }
                issues_data.append(issue_to_xlsx)
                issue_cnt += 1

                if add_only_first:
                    break

def write_log(issues_dict, to_ver_default, issues_log, add_only_first=False):
    if add_only_first:
        log_start = f'Issues with no direct upgrade or patch:\n'
    else:
        log_start = f'Issues to fix by upgrading:\n'

    long_log.append(log_start)

    tmp_log_stack = ''
    for key, value in issues_dict.items():
        tmp_log = ''
        first_issue = value['issues'][0]
        severity = first_issue['issueData']['severity'].capitalize()
        tmp_log += f'\tUpgrade {first_issue['pkgName']}@{first_issue['pkgVersions']} to {first_issue['pkgName']}@{value.get('patchversion', to_ver_default)} to fix\n'

        for i in value['issues']:
            tmp_log += f'\t✗ {i['issueData']['title']} [{severity} Severity] [{i['issueData']['url']}] in {i['pkgName']}@{i['pkgVersions']}\n'
            tmp_log += f'\t  introduced by {i['pkgName']}@{i['pkgVersions']}\n'
        tmp_log += f'\n'

        if tmp_log_stack.count('\n') + tmp_log.count('\n') >= 100:
            long_log.append(tmp_log_stack)
            tmp_log_stack = ''
            tmp_log_stack = tmp_log
        else:
            tmp_log_stack += tmp_log
    if tmp_log_stack != '':
        long_log.append(tmp_log_stack)

def filter_json_data(path):
    with open(path, 'r') as f:
        data = json.load(f)

    issues_log = ''
    severity_cnt = {}

    if data and isinstance(data, dict):
        project_key = next(iter(data))
        project_issues = data[project_key]
        severity_cnt = project_issues.get('severity_cnt', {})
    else:
        print('데이터가 없거나 올바른 형식이 아닙니다.')

    xlsx_issues_y = project_issues.get('vulnerabilities').get('patch_y')
    xlsx_issues_n = project_issues.get('vulnerabilities').get('patch_n')

    process_issues(xlsx_issues_y, 'N/A')
    process_issues(xlsx_issues_n, 'N/A', add_only_first=True)

    write_log(xlsx_issues_y, 'N/A', issues_log)
    write_log(xlsx_issues_n, 'N/A', issues_log, add_only_first=True)

    filtered_data = {
        "severity": severity_cnt,
        "issues": issues_data,
        "log": long_log
    }

    return filtered_data

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('input_json', help='대상 JSON 파일 경로')
    args = parser.parse_args()

    with open(args.input_json, 'r') as f:
        data = json.load(f)

    filtered_data = filter_json_data(data)
