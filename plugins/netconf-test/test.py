

json_data = {'dst': '1111:4::2/128', 'action': 'End.DT6', 'vrftable': '254', 'dev': 'ens192'}
if "table" in json_data:
    print("yes")
if "vrftable" in json_data:
    print("no")