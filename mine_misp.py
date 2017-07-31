"""
    Pulls most valuable information from the MISP data dumps
    
    :author Connor
"""

import json
considerable_sources = ['NCSC-NL', 'RiskIQ', 'CIRCL', 'TRUESEC.be', 'CthulhuSPRL.be',
                        'CERT-BUND_4403', 'BASF.de', 'CUDESO', 'Crimeware', 'INCIBE', ]

if __name__ == '__main__':
    with open('misp.json', 'r') as json_file:
        misp_file = json.load(json_file)['response']['Event']
        orgc_set = set()
        # Get all unique contributing orgs names
        for item in misp_file:
            if item['Orgc'] is not None:
                orgc_set.add(item['Orgc']['name'])

        # Reorganize json by organization
        source_dict = {}
        filtered_source_dict = {}
        for orgc in orgc_set:
            source_dict[orgc] = []
            filtered_source_dict[orgc] = {}

        for orgc in orgc_set:
            for item in misp_file:
                if item['Orgc']['name'] == orgc:
                    source_dict[orgc].append(item)

        # Find the 'category' of all these (Threat Category)
        for orgc in orgc_set:
            category_set = set()
            data_type_set = set()
            date_list = []
            entry_count = 0
            for orgc_value in source_dict[orgc]:
                if orgc_value['Attribute'] is not None:
                    entry_count += len(orgc_value['Attribute'])
                    for item in orgc_value['Attribute']:
                        if type(item) == dict and item is not None:
                            category_set.add(item['category'])
                            data_type_set.add(item['type'])
                if orgc_value['date'] is not None:
                    date_list.append(orgc_value['date'])

            date_list.sort()
            filtered_source_dict[orgc]['indicator_count'] = entry_count
            filtered_source_dict[orgc]['category'] = ', '.join(category_set)
            filtered_source_dict[orgc]['type'] = ', '.join(data_type_set)
            filtered_source_dict[orgc]['distribution'] = orgc_value['distribution']
            filtered_source_dict[orgc]['timestamp'] = orgc_value['timestamp']
            filtered_source_dict[orgc]['date'] = {
                'first': date_list[0],
                'recent': date_list[-1],
                'total_posted': len(date_list)
            }


        print '--------------------------'
        name = 'CthulhuSPRL.be'
        for value in filtered_source_dict[name]:
            print value, filtered_source_dict[name][value]
