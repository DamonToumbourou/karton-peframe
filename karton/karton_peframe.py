import sys
sys.path.append('./')

from karton.core import Config, Karton, Task, Resource
from mwdblib import MWDB
from peframe import peframe_custom
import os

class PeframeKarton(Karton):
  identity = "karton.peframe"
  filters = [{"type": "sample", "stage": "recognized"}]

  def process(self, task: Task) -> None:
    api_key = os.environ["API_KEY"]
    api_url = os.environ["API_URL"]

    # Get the incoming sample
    sample_resource = task.get_resource("sample")

    # Log with self.log
    self.log.info(f"Running static analysis on sample: {sample_resource.name}.")

    # Download the resource to a temporary file
    with sample_resource.download_temporary_file() as sample_file:
      # And process it
      result = get_peframe.run(sample_file.name)
      print("sample name: ", sample_resource)
      print(result)

      # upload result as config
      mwdb = MWDB(api_key=api_key, api_url=api_url).upload_config(family="", cfg=result, config_type="PEframe", parent=sample_resource.sha256, tags=result["File Information"]["filetype"])

if __name__ == "__main__":
    # Here comes the main loop
    PeframeKarton().loop()
