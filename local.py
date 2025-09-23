import json
import pandas as pd
import os
from datetime import datetime
import jsonlines
import yaml

def get_text_from_file(file_path):
    """Reads content from a text file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return None
def parse_json_object(json_string):
    """Parses a JSON string into a Python dictionary."""
    try:
        data = json.loads(json_string)
        return list(data.keys()) 
    except json.JSONDecodeError:
        print("Error: Invalid JSON format")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def load_rules_from_alerts(alerts_df):
    rules_dict = {}
    json_alerts = json.loads(alerts_df.to_json(orient="records"))
    for alert in json_alerts:
        rules_dict[alert["trigger_id"]] = {
            "rule_id": alert.get("trigger_id","N/A"),
            "message": alert.get("message","N/A"),
            "search": alert.get("search","N/A") + alert.get("tuning_search",""),
            "severity": alert.get("severity","N/A"),
            "description": alert.get("description","N/A"),
            "seconds_threshold": alert.get("seconds_threshold","60"),
            "events_threshold": alert.get("events_threshold","1"),
            "is_tuned": alert.get("is_tuned",False),
            "distinguishers": parse_json_object(alert.get("distinguishers","[]")) 
            }
    return rules_dict

def load_rules_from_directory(directory_path):
    """Load rule definitions from JSON files in a local directory."""
    rules = []

    try:
        # List all JSON files in the directory
        rule_files = [f for f in os.listdir(directory_path) if f.endswith('.json')]
        print(f"Found {len(rule_files)} rule files in directory.")

        # Process each rule file
        for file_name in rule_files:
            file_path = os.path.join(directory_path, file_name)

            with open(file_path, 'r') as file:
                rule_data = json.load(file)

            # Add the filename as source for reference
            rule_data['source_file'] = file_name
            rules.append(rule_data)

        print(f"Successfully loaded {len(rules)} rule definitions.")
        return rules

    except Exception as e:
        print(f"Error loading rules from directory: {e}")
        return []

def load_alerts_from_file(file_path):
    """Load alert data from a local JSON file."""
    # [This function remains the same as in our previous code]
    try:
        try:
            with jsonlines.open(file_path, 'r') as f:
                alerts_data = []
                for alert in f:
                    alerts_data.append(alert)
        except:
            with open(file_path, 'r') as f:
                alerts_data = json.load(f)
        df = pd.DataFrame(alerts_data)
        print(f"Loaded {len(df)} alerts.")
        return df
    except FileNotFoundError:
        print(f"Error: Alert file not found at {file_path}")
        return pd.DataFrame()
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in alert file at {file_path}")
        return pd.DataFrame()
    except Exception as e:
        print(f"An unexpected error occurred loading alerts: {e}")
        return pd.DataFrame()


def parse_helix_alert_details(alerts_df: pd.DataFrame) -> pd.DataFrame:

    # Example parsing for the "__metadata__" field if it's a JSON string
    if '__metadata__' in alerts_df.columns:
        alerts_df['parsed_customer_id'] = None # Initialize new column

        # Iterate through rows to parse metadata and extract customer_id
        for index, row in alerts_df.iterrows():
            metadata_raw = row.get('__metadata__')
            if isinstance(metadata_raw, str):
                try:
                    metadata_dict = json.loads(metadata_raw)
                    alerts_df.at[index, 'parsed_customer_id'] = metadata_dict.get('customer_id')
                except json.JSONDecodeError:
                    alerts_df.at[index, 'parsed_customer_id'] = None # Handle invalid JSON string
            elif isinstance(metadata_raw, dict): # If __metadata__ is already a dict
                 alerts_df.at[index, 'parsed_customer_id'] = metadata_raw.get('customer_id')

    # Ensure 'instance' or 'parsed_customer_id' is used for customer instance grouping
    # Prioritize 'instance' if it exists and is not None/empty
    alerts_df['customer_instance'] = alerts_df.apply(
        lambda row: row.get('instance') or row.get('parsed_customer_id'), axis=1
    )

    # Ensure 'rule_id' exists, perhaps mapping from 'trigger_id' or 'id'
    if 'trigger_id' in alerts_df.columns:
        alerts_df['rule_id'] = alerts_df['trigger_id']
    elif 'id' in alerts_df.columns:
        alerts_df['rule_id'] = alerts_df['id'] # Using 'id' as a fallback for rule_id
    else:
        alerts_df['rule_id'] = 'UNKNOWN_RULE' # Default if no ID field

    # You might want to extract other fields needed for the prompt directly here
    # For now, we rely on the access within analyze_soc_alerts_from_json
    print("Helix alert details parsed.")
    return alerts_df


def match_alerts_to_rules(alerts_df):
    """Match alerts to their corresponding rule definitions."""
    # Create a lookup dictionary for quick rule access
    rule_dict = load_rules_from_alerts(alerts_df)

    # Add rule definition to the alerts dataframe
    alerts_df['rule_definition'] = alerts_df['trigger_id'].apply(lambda x: rule_dict.get(x, {}))
    # Count how many alerts were matched to rules
    matched_count = len(alerts_df[alerts_df['rule_definition'].apply(lambda x: x != {})])
    print(f"Matched {matched_count} out of {len(alerts_df)} alerts to rule definitions.")

    return alerts_df,rule_dict

def local_main(alerts_file):

    # 1. Load alert data from local file
    print(f"Loading alert data from {alerts_file}...")
    alerts_df = load_alerts_from_file(alerts_file)

    if alerts_df.empty:
        print("No alerts loaded. Exiting.")
        return []

    # 3. Match alerts to rules
    print("Matching alerts to rule definitions...")
    matched_alerts,rule_dict = match_alerts_to_rules(alerts_df)

    # 4. Parse Helix-specific data
    print("Parsing Helix alert details...")
    parsed_alerts = parse_helix_alert_details(pd.DataFrame(matched_alerts))

    # 5. Group alerts by rule ID to identify patterns
    rule_groups = parsed_alerts.groupby('rule_id')

    # Rest of the code continues as before...
    print("Grouping alerts by rule ID...")
    for rule_id, group in rule_groups:
        print(f"\n--- Alerts for Rule ID: {rule_id} ---")
        # Here you would typically process each group, e.g., send to LLM
        # For demonstration, we'll just print a summary
        print(f"Number of alerts: {len(group)}")
        print(f"States: {group['state'].unique().tolist()}")
        print(f"Closed States: {group['closed_state'].unique().tolist()}")
    return parsed_alerts,rule_dict


