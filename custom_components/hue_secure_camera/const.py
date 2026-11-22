"""Constants for the Hue Secure Camera integration."""

DOMAIN = "hue_secure_camera"

# Config entry keys
CONF_BEARER_TOKEN = "bearer_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_HOME_ID = "home_id"
CONF_E2EE_PASSPHRASE = "e2ee_passphrase"
CONF_DEVICE_MAC = "device_mac"
CONF_DEVICE_NAME = "device_name"

# Auth0 public client (extracted from the official Hue app)
CLIENT_ID = "xOFEN65uPEwp0aMlJ6JA1CK2slFyZtGQ"
REDIRECT_URI = "https://account.meethue.com/"
AUTH_URL = "https://auth.meethue.com/authorize"
TOKEN_URL = "https://auth.meethue.com/oauth/token"
SCOPE = "openid offline_access"
AUDIENCE = "https://account.meethue.com"

# Hue Secure cloud API
HUE_API_BASE = "https://api.account.meethue.com"
HUE_DEVICES_URL = HUE_API_BASE + "/security/device-configuration/v1/home/{home_id}/device"
HUE_WAKE_URL = (
    HUE_API_BASE
    + "/security/device-configuration/v1/home/{home_id}/device/{device_id}/command"
)
HUE_LIVE_STREAM_URL = (
    HUE_API_BASE + "/security/vss/v1/home/{home_id}/credentials/live-stream?turn_servers=true"
)

# Token handling
TOKEN_EXPIRY_BUFFER_SECONDS = 300

# Streaming
FRAME_MAX_AGE_SECONDS = 15
