import os
from datetime import datetime

dirname = "/Users/pavanpothamsetti/Documents/projects/blackboard/final_proj"
rule_id = "1.1.1.4"
folder_path = f"{dirname}/outputs/{datetime.now().strftime('%Y%m%d')}"
if not os.path.isdir(folder_path):
    os.mkdir(folder_path)
report_path = os.path.join(f"{dirname}/outputs/{datetime.now().strftime('%Y%m%d')}", f"report_{rule_id}.txt")

with open(report_path,"w+") as f:
    f.write("hey")
