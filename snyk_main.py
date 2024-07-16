import sys
import json
import importlib.util
from to_xlsx_report import json_to_xlsx
from filter_to_xlsx import filter_json_data

def import_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

def main():
    get_snyk_path = 'get_issues_by_project-id.py'
    get_snyk_module_name = 'get_issues_by_project_id'
    #project_id = input('프로젝트 ID를 입력하세요: ')
    project_id = 'ba31ee21-fc9d-4cc7-9386-dfdede1be586'

    get_snyk_module = import_module_from_path(get_snyk_module_name, get_snyk_path)

    json_path = get_snyk_module.generate_snyk_report(project_id)

    filtered_json_data = filter_json_data(json_path)


    xlsx_path = f'report/{json_path.replace('.json', '.xlsx')}'
    xlsx_json_data = json_to_xlsx(filtered_json_data)




if __name__ == "__main__":
    main()
