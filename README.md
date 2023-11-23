# project-r-vision-
Код для тестирования над файлом "тест на 3 уязвимости.oval.xml"


## код 

Файл "тест на 3 уязвимости.oval.xml" сокращен до трёх уязвимостей для быстрой работы программы

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

        simplified_json = json.dumps(simplified_data, indent=4)
        print(simplified_json)

        return simplified_data

    except Exception as e:
        print(f"Ошибка при обработке файла: {e}")
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




