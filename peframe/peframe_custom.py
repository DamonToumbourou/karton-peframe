from peframe import peframe
import json
import os

def get_info(result):
  
  """ 
    File Information
  """
  filename = os.path.basename(result['filename'])
  filetype = result['filetype'][0:63]
  sha256 = result['hashes']['sha256']
  virustotal = str(result['virustotal']['positives']) +'/'+ str(result['virustotal']['total'])
  
  file_information = {"filename": filename, "filetype": filetype, "sha256": sha256, "virustotal": virustotal}
     
  # docinfo
  if result['docinfo']:
    if result['docinfo']['macro']:
      file_information = {"macro": True}


  if result['peinfo']:
    if hex(result['peinfo']['imagebase']) == '0x400000':
      imagebase = hex(result['peinfo']['imagebase'])
    else:
      imagebase = hex(result['peinfo']['imagebase'])+" *"
    imagebase = imagebase
    entrypoint = hex(result['peinfo']['entrypoint'])
    imphash = result['peinfo']['imphash']
    datetime = result['peinfo']['timestamp']
    dll = result['peinfo']['dll']
    

    file_information["imagebase"] = imagebase
    file_information["entrypoint"] = entrypoint
    file_information["imphash"] = imphash
    file_information["datetime"] = datetime
    file_information["dll"] = dll

    # directories
    if result['peinfo']['directories']:
      directories_list = [k for k,v in result['peinfo']['directories'].items() if v]
      directories_list_temp = list(directories_list)
      if result['peinfo']['directories']['resources']:
        for item in result['peinfo']['directories']['resources']:
          if item['executable'] == True:
            try:
              directories_list_temp.remove('resources')
              directories_list_temp.append('resources *')
            except:
              pass
      if directories_list:
        directories = directories_list_temp
        file_information["directories"] = directories


    # sections
    if result['peinfo']['sections']:
      section_list = [items['section_name'] for items in result['peinfo']['sections']['details']]
      section_list_temp = list(section_list)
      for items in result['peinfo']['sections']['details']:
        if items['entropy'] > 6:
          section_list_temp.remove(items['section_name'])
          section_list_temp.append(items['section_name'] + ' *')
      if section_list:
        sections =  section_list_temp
        file_information["sections"] = sections

    # features
    if result['peinfo']['features']:
      features_list = [k for k,v in result['peinfo']['features'].items() if v]
      if features_list:
        features = features_list
        file_information["features"] = features
    
    
    config = {"File Information": file_information}

    # behavior
    if result['peinfo']['behavior']:
      behavior = result['peinfo']['behavior']
      config["Behavior"] = behavior


    # metadata
    if result['peinfo']['metadata']:
      metadata = result['peinfo']['metadata']
      config["metadata"] = metadata

    # breakpoint
    if result['peinfo']['breakpoint']:
      _breakpoint = result['peinfo']['breakpoint']
      config["Breakpoint"] = _breakpoint


  # strings
  if result['strings']:
    if result['strings']['ip']:
      config["Ip Address"] = result['strings']['ip']

    if result['strings']['url']:
      config["Url"] = result['strings']['url']

    if result['strings']['file']:
      config["File"] = result['strings']['file']

    if result['strings']['fuzzing']:
      config["Fuzzing"] = result['strings']['fuzzing']

   
  # docinfo
  if result['yara_plugins']:
    config["Yara Plugins"] = result['yara_plugins']


  if result['docinfo']:
    if result['docinfo']['behavior']:
        config["Behavior"] = result['docinfo']['behavior']

    if result['docinfo']['attributes']:
      header('Attributes')
      for item in result['docinfo']['attributes']:
        print (item)
        config["Behavior"] = result['docinfo']['behavior']
  


  """ 
    Behavior
  """

  return json.dumps(config)


def run(filename):
   

    result = peframe.analyze(filename)
    return get_info(result)