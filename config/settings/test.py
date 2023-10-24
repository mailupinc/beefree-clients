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

# Billing Portal
BILLING_PORTAL_API_BASE_URL = "https://pre-bee-billing-portal.getbee.info/api/"
BILLING_PORTAL_SUBSCRIPTION_URI = "subscriptions/"
BILLING_PORTAL_CHARGIFY_SUBSCRIPTION_URI = "chargify-subscriptions/"
BILLING_PORTAL_GET_RENEWALS_URI = "renewals/"
BILLING_PORTAL_GET_RENEWAL_CHARGES_URI = "renewal-charges/"
BILLING_PORTAL_USER_QUANTITY_URI = "user-quantity/"
BILLING_PORTAL_GET_CATALOG_URI = "plans/"
BILLING_PORTAL_GET_PRICES_URI = "prices/"
BILLING_PORTAL_GET_PAYMENTS_URI = "payments/"
BILLING_PORTAL_GET_IFRAME_CONFIG_URI = "iframe-config/"
BILLING_PORTAL_SET_NEW_PAYMENT_URI = "set-new-payment/"
BILLING_PORTAL_UPDATE_ACCOUNT_URI = "account/"
BILLING_PORTAL_INVOICES_URI = "invoices/"

NOTIFICATION_CENTER_URL = "https://pre-bee-notification-center.getbee.info"

BACKEND_BASE_URL = "https://base_be.url.tld"
