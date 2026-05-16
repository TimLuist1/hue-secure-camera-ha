"""Constants for Hue Secure Camera integration."""

DOMAIN = "hue_secure_camera"

# Config entry keys
CONF_BEARER_TOKEN = "bearer_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_HOME_ID = "home_id"
CONF_E2EE_PASSPHRASE = "e2ee_passphrase"
CONF_BRIDGE_IP = "bridge_ip"
CONF_BRIDGE_KEY = "bridge_api_key"
CONF_DEVICE_MAC = "device_mac"
CONF_DEVICE_NAME = "device_name"
CONF_AWS_REGION = "aws_region"
CONF_CHANNEL_ARN = "channel_arn"

# Hue Cloud API
HUE_API_BASE = "https://api.account.meethue.com"
HUE_TOKEN_URL = "https://api.meethue.com/v2/oauth2/token"
HUE_AUTH_URL = "https://api.meethue.com/v2/oauth2/authorize"
HUE_LIVE_STREAM_URL = (
    "{base}/security/vss/v1/home/{home_id}/credentials/live-stream?turn_servers=true"
)
HUE_WAKE_UP_URL = (
    "{base}/security/device-configuration/v1/home/{home_id}/device/{device_id}/command"
)
HUE_E2EE_KEY_URL = (
    "{base}/security/E2EE-public-keys-service/v1/home/{home_id}/e2ee/public-key"
    "?key_type=home_signing_public_key"
)
HUE_BRIDGE_CAMERAS_URL = "https://{bridge_ip}/api/{api_key}/resourcelinks"

# Token refresh
TOKEN_EXPIRY_BUFFER_SECONDS = 300  # Refresh 5 minutes before expiry

# Stream
STREAM_TIMEOUT_SECONDS = 30
STREAM_KEEPALIVE_INTERVAL = 25
FRAME_QUEUE_SIZE = 30
MJPEG_FRAMERATE = 15

# FrameCryptor key index used by Hue
E2EE_KEY_INDEX = 0

# PBKDF2 parameters (reverse-engineered from Hue app)
PBKDF2_HASH = "sha256"
PBKDF2_ITERATIONS = 100000
PBKDF2_KEY_LEN = 32  # 256 bit master key

# Kyber768 parameters
KYBER768_PUBLIC_KEY_LEN = 1184
KYBER768_SECRET_KEY_LEN = 2400
KYBER768_CIPHERTEXT_LEN = 1088
KYBER768_SHARED_SECRET_LEN = 32
