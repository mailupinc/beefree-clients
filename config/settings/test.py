import logging

from .base import *  # noqa

logging.disable(logging.CRITICAL)

# BEEPRO PROXY
BEEPRO_PROXY_API_KEY = "fake_key"
BEEPRO_PROXY_URL = "https://pre-bee-beepro-proxy.getbee.info"

# Toplyne
TOPLYNE_API_URL = "https://api.toplyne.io"
TOPLYNE_API_TOKEN = ""

TDV_API_URL = "https://tdv.growens.io:9402/"
TDV_USER = "test_user"
TDV_PASSWORD = "test_password"


# PARTNERSTACK
PARTNERSTACK_CUSTOMER_URL = ""
PARTNERSTACK_USER = ""
PARTNERSTACK_PASSWORD = ""
PARTNERSTACK_IGNORE_ERRORS = False

# EHAWK
EHAWK_API_URL = "https://api.ehawk.net"
EHAWK_FEED_API_URL = "https://feed-api.ehawk.net"
EHAWK_APY_KEY = ""
EHAWK_PASSING_LIMIT_SCORE = -50
EHAWK_PASSING_BLOCK_SCORE = -100
EHAWK_ENABLED = False
EHAWK_ENABLE_BLOCK_SCORE = False

# ZAPIER
ZAPIER_BASE_URL = "https://hooks.zapier.com/hooks/catch/"
ZAPIER_SUBSCRIPTION_CRUD_ZAP_PATH = "6002268/oebygeo/"  # Testing Path
ZAPIER_NEW_USER_ZAP_PATH = "10076726/bl7ioe3/"  # Testing Path
ZAPIER_NEW_TRIAL_ZAP_PATH = "10076726/bl7ioe3/"  # Testing Path
ZAPIER_CALLS_ENABLED = True
OLD_ZAPIER_BASE_URL = "https://hooks.zapier.com/hooks/catch/fake/"

# Billing Portal
BILLING_PORTAL_API_KEY = ""
BILLING_PORTAL_MAX_PREVIEW_PARALLEL_CALLS = 1

BEE_EAR_BASE_URL = ""
BEE_EAR_APPLICATION = ""

# Data Service
DATA_SERVICE_URL = ""
DATA_SERVICE_API_KEY = ""
DATA_SERVICE_CALLS_ENABLED = True

# Hook Service
HOOK_SERVICE_BASE_URL = ""
HOOK_SERVICE_CALLS_ENABLED = True
