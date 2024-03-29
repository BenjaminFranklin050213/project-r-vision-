# Выполненное задание для стажера Нисимов М.С.

## 1. Ответы на поставленные аналитические вопросы находятся в .docx файле. Также в файле прописаны мои заметки по заданиям (выделены красным). Помимо прочего, там прописаны заметки по упрощению файла .OVAL и коментарии к написанному коду на python.

## 2. Файл "тест на 3 уязвимости.oval.xml"- это сокращённый файл изначального .OVAL. Он сокращен до трёх уязвимостей для быстрой работы программы.

## 3. Программа 

Код для тестирования над файлом "тест на 3 уязвимости.oval.xml" написанный на Python.

```
from defusedxml.ElementTree import parse
import json

def parse_oval(file_path):
    try:
        tree = parse(file_path)
        root = tree.getroot()

        definitions = root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition')

        simplified_data = []
        for definition in definitions:
            definition_id = definition.get('id')
            title = definition.find('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}title').text

            cve_elements = definition.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata/{http://oval.mitre.org/XMLSchema/oval-definitions-5}reference[@source="CVE"]')
            cve_list = [cve_element.get('ref_id') for cve_element in cve_elements] if cve_elements else None

            description_element = definition.find('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}description')
            description = description_element.text if description_element is not None else None

            criteria_list = []
            criteria_elements = definition.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria') 
            for criteria in criteria_elements:
                criteria_data = extract_criteria(criteria)
                if criteria_data:
                    criteria_list.append(criteria_data)

            simplified_data.append({
                'id': definition_id,
                'title': title,
                'cve': cve_list if cve_list else [],
                'description': description,
                'criteria': criteria_list
            })

        simplified_json = json.dumps(simplified_data)
        return simplified_data

    except Exception as e:
        return None

def extract_criteria(criteria_element):
    criteria_data = {'operator': criteria_element.get('operator')}
    criteria_list = []

    for criterion in criteria_element.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion'):
        criterion_data = {
            'comment': criterion.get('comment'),
            'test_ref': criterion.get('test_ref')
        }
        criteria_list.append(criterion_data)

    sub_criteria_elements = criteria_element.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria')
    for sub_criteria_element in sub_criteria_elements:
        sub_criteria_data = extract_criteria(sub_criteria_element)
        if sub_criteria_data:
            criteria_list.append(sub_criteria_data)

    if criteria_list:
        criteria_data['criteria'] = criteria_list

    return criteria_data

file_path = 'тест на 3 уязвимости.oval.xml'
parse_oval(file_path)
```




