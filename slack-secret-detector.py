from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import re

client = WebClient(token='xoxb-your-slack-token')

# Fetch all public Slack channels
def get_all_public_channels():
    try:
        channels = []
        next_cursor = None
        while True:
            # Paginate through Slack API to get all channels
            response = client.conversations_list(
                types="public_channel",
                cursor=next_cursor
            )
            channels.extend(response['channels'])
            next_cursor = response.get('response_metadata', {}).get('next_cursor')
            if not next_cursor:
                break
        return {channel['name']: channel['id'] for channel in channels}
    except SlackApiError as e:
        print(f"Error fetching channels: {e.response['error']}")
        return {}

# Fetch messages from a given channel
def fetch_messages(channel_id):
    try:
        messages = []
        next_cursor = None
        while True:
            response = client.conversations_history(
                channel=channel_id,
                cursor=next_cursor
            )
            messages.extend(response['messages'])
            next_cursor = response.get('response_metadata', {}).get('next_cursor')
            if not next_cursor:
                break
        return messages
    except SlackApiError as e:
        print(f"Error fetching messages from channel {channel_id}: {e.response['error']}")
        return []

# Scan messages for secrets based on defined patterns
def scan_for_secrets(messages):
    secret_patterns = [
        r'[A-Za-z0-9]{40}',  # Generic key pattern
        r'(AKIA[0-9A-Z]{16})',  # AWS Access Key ID pattern
        r'[A-Za-z0-9-_]{35,45}',  # Generic API token length pattern
        r'[a-zA-Z0-9_=-]{20,40}',  # Basic Auth/Base64 Token pattern
    ]
    
    found_secrets = []
    
    for message in messages:
        for pattern in secret_patterns:
            if re.search(pattern, message.get('text', '')):
                found_secrets.append(message['text'])
                break  # Skip checking other patterns once a match is found
    
    return found_secrets

# Post alert to security channel
def post_alert(channel, message):
    try:
        client.chat_postMessage(channel=channel, text=f"Secret detected: {message}")
    except SlackApiError as e:
        print(f"Error posting alert: {e.response['error']}")

# Main function to scan all public channels
def scan_all_public_channels():
    channels = get_all_public_channels()
    
    if not channels:
        print("No public channels found.")
        return
    
    for channel_name, channel_id in channels.items():
        print(f"Scanning channel: {channel_name} (ID: {channel_id})")
        
        # Fetch messages for the current channel
        messages = fetch_messages(channel_id)
        
        # Scan messages for secrets
        secrets_found = scan_for_secrets(messages)
        
        # If secrets are found, post an alert
        if secrets_found:
            for secret in secrets_found:
                post_alert('security-alerts', secret)  # Replace with your security channel ID
                print(f"Secret found and alert posted for channel {channel_name}")
        else:
            print(f"No secrets found in channel {channel_name}")

# Run the scan across all public channels
if __name__ == "__main__":
    scan_all_public_channels()
