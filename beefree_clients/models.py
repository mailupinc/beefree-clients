import datetime
import json
import logging
import random
import re
from collections import Counter
from copy import copy

from allauth.account.adapter import get_adapter
from allauth.account.models import EmailAddress
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, Permission, PermissionsMixin
from django.contrib.sites.models import Site
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.mail import send_mail
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import RegexValidator
from django.db import models, transaction
from django.db.models import JSONField, ProtectedError, Q
from django.urls import resolve
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from django_q.tasks import async_task
from invitations import signals
from invitations.app_settings import app_settings as invitations_settings
from invitations.base_invitation import AbstractBaseInvitation
from model_utils import Choices
from model_utils.models import StatusField, TimeStampedModel
from rest_framework import status

from beepro_agency_app.active_campaign import update_AC_contact
from beepro_agency_app.clients import PartnerstackClient, ZapierClient
from beepro_agency_app.models import SoftDeletableModel
from beepro_agency_app.utils import async_wrapper, convert_tokens_to_words

# FIXME: refactor and remove this import
from beepro_agency_users.billing import BillingAccount

from .exceptions import InvalidTransition, OfflineSubscriptionException, SeatError, SubscriptionException
from .fields import JSONMonitorField
from .managers import (
    CronJobSubscriptionManager,
    CustomerAiTokensManager,
    CustomerManager,
    LivingSubscriptionManager,
    MembershipManager,
    NoBillingSeatManager,
    SeatManager,
    SubscriptionManager,
    TrialSubscriptionManager,
    UserManager,
    UserScoreManager,
)

logger = logging.getLogger(__name__)


class MailupUser(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    Username, password and email are required. Other fields are optional.
    """

    first_name = models.CharField(_("first name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH, blank=True)
    last_name = models.CharField(_("last name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH, blank=True)
    email = models.EmailField(_("email address"), unique=True, max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin " "site."),
    )
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Designates whether this user should be treated as " "active. Unselect this instead of deleting accounts."
        ),
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)
    extra_params = models.TextField(_("extra params"), null=True, blank=True)
    notifications_enabled = models.BooleanField(_("notifications enabled"), default=True)
    remember_me = models.BooleanField(_("remember me"), default=False)
    otp_due_date = models.DateTimeField(_("otp_due_date"), blank=True, null=True)
    otp_uuid = models.UUIDField(_("otp uuid"), null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "email"

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        swappable = "AUTH_USER_MODEL"
        permissions = [("impersonate_user", "Can impersonate another user")]

    def delete_real(self, using=None, keep_parents=False, *args, **kwargs):
        return super().delete(using, keep_parents, *args, **kwargs)

    @cached_property
    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.strip()

    @cached_property
    def get_short_name(self):
        """
        Returns the short name for the user.
        """
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    @property
    def primary_address(self):
        return EmailAddress.objects.get_primary(self)

    @cached_property
    def customers(self):
        return self.memberships.values_list("customer", flat=True)

    def role(self, customer):
        try:
            return self.memberships.get(customer__pk=customer)
        except Exception:
            pass

    def set_current_role(self, customer):
        self.current_role = self.role(customer)

    def get_current_role(self):
        try:
            return self.current_role
        except AttributeError:
            return

    @cached_property
    def current_customer(self):
        try:
            return self.current_role.customer
        except AttributeError:
            return

    @property
    def shard(self):
        try:
            return self.get_current_role().customer.shard
        except AttributeError:
            return settings.DATABASE_SHARDS_CURRENT

    @property
    def email_address(self):
        try:
            # Get 'allauth' primary email address
            return self.emailaddress_set.filter(primary=True).first().email
        except Exception:
            return self.email

    def get_plan(self):
        try:
            return self.current_subscription.application_plan
        except AttributeError:
            return None

    @property
    def subscription_status(self):
        try:
            return self.current_subscription.status
        except AttributeError:
            return None

    @property
    def email_verified(self):
        return True if self.primary_address and self.primary_address.verified else False

    @cached_property
    def subscriptions(self):
        # All subscription owned by the user (Owner)
        role = Role.objects.get(name=settings.ROLES[settings.OWNER])
        customer_ownerships = self.memberships.filter(role=role.pk).values_list("customer", flat=True)
        return Subscription.objects.filter(customer__in=customer_ownerships)

    @cached_property
    def current_subscription(self):
        # Current subscrition related to some Customer on the hierarchy
        try:
            customer = self.get_current_role().customer
            return Subscription.objects.get(customer=customer)
        except (AttributeError, Subscription.DoesNotExist):
            return None

    def brands(self, customer):
        from beepro_agency_messages.models import BrandPermission

        return BrandPermission.objects.filter(user_id=self.pk).values_list("brand", flat=True)

    def init_from_request(self, request):
        """
        Initialize user when authenticated from the request. We can't do this in the normal init
        thus we have to call it afterwards

        :param request: Django request object
        """

        # TODO: REFACTORING NEEDED
        resolved_request = resolve(request.path_info)
        kwargs = resolved_request.kwargs
        customer = None

        url_name = resolved_request.url_name or ""

        if url_name in ("customers-detail", "customers-collaboration-proxy"):
            customer = int(kwargs["pk"])

        elif url_name.startswith("trial-features"):
            if subscription_pk := kwargs.get("parent_lookup_subscription_id"):
                try:
                    subscription = Subscription.objects.get(id=subscription_pk)
                    customer = subscription.customer.pk
                except Subscription.DoesNotExist:
                    pass
        elif url_name.startswith("subscriptions"):
            if subscription_pk := kwargs.get("pk"):
                try:
                    subscription = Subscription.objects.get(id=subscription_pk)
                    customer = subscription.customer.pk
                except Subscription.DoesNotExist:
                    pass
        else:
            for key in kwargs.keys():
                if settings.ROOT_FILTER in key:
                    customer = int(kwargs[key])

        self.set_current_role(customer)

    def delete_user_related_objects(self):
        owner_role = Role.objects.get(name=settings.ROLES[settings.OWNER])
        membership = Membership.objects.filter(user=self, role=owner_role).first()
        if membership:
            customer = membership.customer
            for brand in customer.brands:
                brand.delete()
            customer.delete()

    @property
    def social_accounts(self):
        return self.socialaccount_set.all()

    @property
    def extra_params_dict(self) -> dict:
        if self.extra_params:
            return json.loads(self.extra_params)
        return copy(settings.SIGNUP_EXTRA_PARAMS)

    def get_bee_free_message_json(self) -> dict:
        params = self.extra_params_dict
        if beefree_message_json := params.pop("beefree_message_json", None):
            self.extra_params = json.dumps(params)
            self.save()
        return beefree_message_json

    @property
    def internal_features_access(self) -> bool:
        if self.groups.filter(name=settings.INTERNAL_FEATURES_GROUP_NAME):
            return True
        return False

    @cached_property
    def has_paid_subscription(self):
        return (
            self.subscriptions.filter(status=Subscription.STATUS_ACTIVE).exclude(plan=Subscription.PLAN_FREE).exists()
        )

    @cached_property
    def has_organization_email(self):
        try:
            if self.has_paid_subscription or self.score.pass_limit_score:
                return self.score.has_organization_email
            return False
        except UserScore.DoesNotExist:
            return None

    @property
    def user_phone(self):
        try:
            return UserPhone.objects.get(user=self)
        except UserPhone.DoesNotExist:
            return None

    @property
    def user_score(self):
        try:
            return self.score
        except UserScore.DoesNotExist:
            return None

    @property
    def show_two_factor_auth(self):
        if self.social_accounts.exists():
            return False

        for membership in self.memberships.all():
            if membership.customer.subscription.application_plan in settings.PLAN_PERMISSIONS["2fa"]:
                return True
        return False

    @property
    def metadata_dict(self):
        try:
            return {
                obj["name"]: obj["value"]
                for obj in self.extra_params_dict["Metadata"]
                if "name" in obj and "value" in obj
            }
        except KeyError:
            return {}


class CustomerStatus(TimeStampedModel, SoftDeletableModel, models.Model):
    name = models.CharField(_("Name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    description = models.TextField(_("Description"), null=True, blank=True)

    class Meta:
        verbose_name = _("customer status")
        verbose_name_plural = _("customer statuses")
        ordering = ("name",)

    def __str__(self):
        return self.name


class Customer(TimeStampedModel, SoftDeletableModel, models.Model):
    name = models.CharField(_("Name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    status = models.ForeignKey(
        CustomerStatus,
        verbose_name=_("status"),
        related_name="+",
        on_delete=models.CASCADE,
    )
    shard = models.CharField(
        _("Shard"),
        max_length=settings.TEXT_FIELD_CHOICES_LENGTH,
        choices=settings.DATABASE_SHARDS,
        default=settings.DATABASE_SHARDS_CURRENT,
    )
    contract_signed = models.BooleanField(_("Contract signed"), default=False)
    contract_signature_date = models.DateTimeField(_("Contract signature date"), blank=True, null=True)
    tos_acceptance_log = JSONField(default=list, encoder=DjangoJSONEncoder, blank=True)
    ORGANIZATION_STATUS = Choices("private", "public_to_approve", "public_auto_approved")
    organization_status = models.CharField(choices=ORGANIZATION_STATUS, max_length=100, null=True)
    industry = models.CharField(max_length=settings.TEXT_FIELD_STANDARD_LENGTH, blank=True)
    ai_tokens = models.IntegerField(null=True, blank=True)  # TO BE REMOVED

    objects = CustomerManager()

    class Meta:
        verbose_name = _("customer")
        verbose_name_plural = _("customers")
        ordering = ("name",)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        created = self.pk is None
        super().save(*args, **kwargs)
        self._enable_merged_pages(created)

    @property
    def owner(self):
        try:
            owner_membership = self.members.get(role__name="Owner")
            return owner_membership.user
        except Exception:
            logger.exception("customer owner not accessible")
            return None

    @property
    def account_id(self):
        """A unique id to be used in all external systems like Pendo, Zuora, CRM etc.."""
        return f"{settings.ACCOUNT_ID_PREFIX}-{self.id}"

    @staticmethod
    def pendo_switch_date():
        switch_date = datetime.datetime.strptime(settings.PENDO_ACCOUNT_ID_SWITCH_DATE, "%Y-%m-%d")
        return timezone.make_aware(switch_date)

    @property
    def pendo_account_id(self) -> str:
        match settings.BEE_ENV.lower():
            case "pro":
                return self.account_id
            case ("pre" | "pre2" | "pre3" | "pre4"):
                prefix = "PRE"
            case _:
                prefix = settings.BEE_ENV.upper()
        return f"{prefix}_{self.account_id}"

    @property
    def brands(self):
        from beepro_agency_messages.models import Brand

        return Brand.objects.filter(customer_id=self.pk)

    @property
    def roles(self):
        if self.subscription.plan == Subscription.PLAN_FREE:
            available_roles = settings.FREE_PLAN_SELECTABLE_ROLES
        else:
            available_roles = settings.STANDARD_SELECTABLE_ROLES
        return Role.objects.filter(name__in=available_roles)

    def update_tos_log(self, version, ip_address=None):
        """Update Tos acceptance log. For legal purposes"""
        if not self.tos_version_already_accepted(version):
            self.tos_acceptance_log.append(
                {
                    "version": version,
                    "datetime": timezone.now().isoformat(),
                    "ip_address": ip_address,
                }
            )

    def tos_version_already_accepted(self, version):
        """Check if version passed as argument has already been accepted"""
        return bool([tos for tos in self.tos_acceptance_log if tos["version"] == version])

    @property
    def first_accepted_tos_version(self):
        """Return TOS version accepted at registration time"""
        current_tos_start = datetime.datetime.strptime(settings.CURRENT_TOS_START_DATE, "%Y-%m-%d")
        current_tos_start = timezone.make_aware(current_tos_start)
        if not self.contract_signed:
            return None
        if not self.contract_signature_date:
            return settings.DEFAULT_TOS_VERSION
        if self.contract_signature_date < current_tos_start:
            return settings.DEFAULT_TOS_VERSION
        return settings.CURRENT_TOS_VERSION

    def populate_tos_log_from_old_data(self):
        """Populate tos acceptance log if empty"""

        if not self.tos_acceptance_log:
            tos_version = self.first_accepted_tos_version
            try:
                datetime = self.contract_signature_date.isoformat()
            except AttributeError:
                datetime = self.created.isoformat()
            self.tos_acceptance_log.append({"version": tos_version, "datetime": datetime, "ip_address": None})
            self.save()

    def _enable_merged_pages(self, created):
        if created and settings.ENABLE_MERGED_PAGES_FOR_NEW_USERS:
            self.feature_flags.create(feature_key="mergedPages", feature_enabled=True)

    def beta_pages_enabled(self):
        return not self.feature_flags.filter(feature_key="BETA-pages-off", feature_enabled=True).exists()

    beta_pages_enabled.boolean = True  # type: ignore

    @cached_property
    def new_projects_page(self):
        return True

    @property
    def is_trial(self):
        try:
            return self.subscription.is_trial
        except Subscription.DoesNotExist:
            return True

    @property
    def is_active(self):
        try:
            return self.subscription.is_active
        except Subscription.DoesNotExist:
            return False

    @property
    def is_third_level_domain_customized(self):
        for brand in self.brands:
            if brand.is_third_level_domain_customized:
                return True
        return False

    @property
    def is_own_domain_customized(self):
        for brand in self.brands:
            if brand.own_domains.count() > 0:
                return True
        return False

    @property
    def has_organization_domain(self):
        return self.owner.has_organization_email

    @cached_property
    def enabled_feature_flags(self):
        return [x.feature_key for x in self.feature_flags.filter(feature_enabled=True)]

    @cached_property
    def autosave_enabled(self):
        try:
            return self.subscription.application_plan not in settings.AGENCY_HANDLES
        except Subscription.DoesNotExist:
            logger_debug = logging.getLogger("debug")
            logger_debug.debug(f"Subscription does not exist for this customer: {self.pk}")
            return False

    @property
    def unpaid_cdn(self):
        return self.customer_cdn_usage.filter(limit_type=CustomerCdnUsage.LIMIT_TYPES.over, paid=False)

    def pay_cdn_usages(self):
        self.unpaid_cdn.update(paid=True)

    @property
    def current_cdn_usages(self):
        return self.customer_cdn_usage.filter(date__range=(self.get_cdn_billing_period()))

    def get_cdn_billing_period(self) -> tuple[datetime.date, datetime.date]:
        billing_data = self.subscription.billing_data
        next_start_cdn_billing_date_str = billing_data["next_secondary_billing_date"]
        next_start_cdn_billing_date = (
            timezone.now().date()
            if next_start_cdn_billing_date_str is None
            else datetime.datetime.strptime(next_start_cdn_billing_date_str, settings.ISO8601_DATE_STRING_FORMAT)
        )
        start_date = next_start_cdn_billing_date - relativedelta(months=1)
        end_date = next_start_cdn_billing_date - relativedelta(days=1)

        return start_date, end_date

    @property
    def messages_count(self):
        from beepro_agency_messages.models import Message

        return Message.objects.filter(project__brand__customer_id=self.pk).count()

    @property
    def projects_count(self):
        from beepro_agency_messages.models import Project

        return Project.standard_objects.filter(brand__customer_id=self.pk).count()

    @property
    def rows_count(self):
        from beepro_agency_messages.models import SavedRow

        return SavedRow.objects.filter(category__brand__customer_id=self.pk).count()

    @property
    def templates_count(self):
        from beepro_agency_messages.models import Template

        return Template.objects.filter(brand__customer_id=self.pk).count()

    @property
    def redis_queue_enabled(self) -> bool:
        return (
            settings.REDIS_QUEUE_ENABLED
            and not self.feature_flags.filter(feature_key="redis-queue-off", feature_enabled=True).exists()
        )


class FeatureFlag(TimeStampedModel, models.Model):
    feature_key = models.CharField(verbose_name=_("feature_key"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    feature_enabled = models.BooleanField(default=False)
    customer = models.ForeignKey(
        Customer,
        verbose_name=_("Customer"),
        help_text="currentCustomer on ZenDesk",
        related_name="feature_flags",
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = (("customer", "feature_key"),)
        verbose_name = _("feature flag")
        verbose_name_plural = _("feature flags")

    def __str__(self):
        return f"{self.feature_key}:{self.feature_enabled}"


def default_customer_config():
    """Default configuration to use during Tiny release of BeePlugin"""
    return {"plugin_label": {"nl": None, "page": None}}


class CanaryCustomer(TimeStampedModel, models.Model):
    """
    Now it manage
    - one boolean enabled/disabled
    - a json field for configuration details

    on every save it sends to pendo the custom variable
    """

    enabled = models.BooleanField(default=False)
    customer_config = JSONField(default=default_customer_config, encoder=DjangoJSONEncoder, blank=True)
    customer = models.OneToOneField(
        Customer,
        verbose_name=_("Canary Customer"),
        help_text="currentCustomer on ZenDesk",
        related_name="canary_customer",
        on_delete=models.CASCADE,
    )

    @property
    def pendo_account_id(self) -> str | None:
        """
        This one will change according to
        new definition of pendo_account_id on subscription or customer
        """
        try:
            return self.customer.pendo_account_id
        except ObjectDoesNotExist:
            return None

    def plugin_label_for(self, product_handle: str) -> str | None:
        try:
            if not self.enabled:
                return None
            return self.customer_config.get("plugin_label", {}).get(product_handle)
        except Exception:
            return None

    @property
    def new_parser_enabled(self) -> bool:
        return (
            self.plugin_label_for("nl") == "beepro-newparser-nl"
            and self.plugin_label_for("page") == "beepro-newparser-page"
        )

    @classmethod
    def read_plugin_label(cls, customer_id: int, product_handle: str) -> str | None:
        try:
            canary_customer = cls.objects.get(customer_id=customer_id)
            plugin_label = canary_customer.plugin_label_for(product_handle)
            return plugin_label
        except Exception:
            return None

    @classmethod
    def read_new_parser_enabled(cls, customer_id: int) -> bool:
        try:
            canary_customer = cls.objects.get(customer_id=customer_id)
            return canary_customer.new_parser_enabled
        except Exception:
            return False

    def configure_to_use_new_parser(self):
        self.configure_plugin_labels(True, "beepro-newparser-nl", "beepro-newparser-page")

    def configure_plugin_labels(self, enabled: bool, plugin_label_nl: str, plugin_label_page: str):
        if self.customer_config is None or not isinstance(self.customer_config, dict):
            self.customer_config = {}

        if "plugin_label" not in self.customer_config:
            self.customer_config["plugin_label"] = {}

        self.customer_config["plugin_label"] = {
            "nl": plugin_label_nl,
            "page": plugin_label_page,
        }
        self.enabled = enabled

    @classmethod
    def create_canary_new_parser(cls, customer):
        cc, _ = cls.objects.get_or_create(customer=customer, defaults={"enabled": True})
        cc.configure_to_use_new_parser()
        cc.save()
        return cc

    class Meta:
        db_table = "beepro_agency_users_canary_customer"


class UserStatus(TimeStampedModel, SoftDeletableModel, models.Model):
    name = models.CharField(_("Name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)

    class Meta:
        verbose_name = _("user status")
        verbose_name_plural = _("user statuses")

    def __str__(self):
        return self.name


class Role(TimeStampedModel, SoftDeletableModel, models.Model):
    name = models.CharField(_("Name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    description = models.TextField(verbose_name=_("Description"), default="", blank=True)
    permissions = models.ManyToManyField(Permission, verbose_name=_("permissions"))
    requires_seat = models.BooleanField(verbose_name=_("Requires Seat"), default=True)  # TODO Remove
    billed_seats = models.BooleanField(verbose_name=_("Requires Seat"), default=True)

    class Meta:
        verbose_name = _("role")
        verbose_name_plural = _("roles")

    def __str__(self):
        return self.name


class Membership(TimeStampedModel, SoftDeletableModel, models.Model):
    COLOR_RE = re.compile("^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")
    color_validator = RegexValidator(COLOR_RE, _("Enter a valid color."), "invalid")

    user_status = models.ForeignKey(
        UserStatus,
        verbose_name=_("user status"),
        related_name="+",
        on_delete=models.CASCADE,
    )
    customer = models.ForeignKey(
        Customer,
        verbose_name=_("customer"),
        related_name="members",
        on_delete=models.CASCADE,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("user"),
        related_name="memberships",
        on_delete=models.CASCADE,
    )
    role = models.ForeignKey(
        Role,
        verbose_name=_("role"),
        related_name="memberships",
        on_delete=models.CASCADE,
    )
    single_brand_user = models.BooleanField(_("Single brand user"), default=False)
    color = models.CharField(
        max_length=7,
        default="",
        blank=True,
        validators=[
            color_validator,
        ],
    )

    PERMISSION_TYPES = Choices("full_access", "content_only")
    permission_type = StatusField(choices_name="PERMISSION_TYPES")

    objects = MembershipManager()

    class Meta:
        verbose_name = _("membership")
        verbose_name_plural = _("memberships")
        ordering = ("modified",)
        unique_together = [["user", "customer", "deleted"]]

    def __str__(self):
        return f"membership {self.role} of user {self.user} in {self.customer}"

    def save(self, *args, **kwargs):
        if not self.color:
            self.set_color()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        from beepro_agency_messages.models import BrandPermission

        for brand in self.customer.brands:
            BrandPermission.objects.filter(user_id=self.user.pk, brand_id=brand.pk).delete()
        return super().delete(*args, **kwargs)

    @property
    def role_permissions(self):
        return self.role.permissions.all()

    def has_perm(self, permission):
        return permission in self.role_permissions

    @property
    def subscription_id(self):
        return self.customer.subscription.subscription_id

    @property
    def subscription_plan(self):
        return self.customer.subscription.plan

    @property
    def subscription_created(self):
        return self.customer.subscription.created

    @property
    def subscription_dunning_status(self):
        return self.customer.subscription.dunning_status

    @property
    def subscription_status(self):
        return self.customer.subscription.status

    @property
    def subscription_max_no_billing_users(self):
        return self.customer.subscription.max_no_billing_users

    @property
    def subscription_cmrr(self):
        return self.customer.subscription.cmrr

    @property
    def subscription_discounts(self):
        if billing_data_discounts := self.customer.subscription.billing_data.get("discounts"):
            return {
                "other": billing_data_discounts.get("other", False),
                "bundle": billing_data_discounts.get("bundle", False),
                "non_profit_50": billing_data_discounts.get("non_profit_50", False),
                "non_profit_10": billing_data_discounts.get("non_profit_100", False),
                "internal": billing_data_discounts.get("internal", False),
            }
        return {
            "other": False,
            "bundle": False,
            "non_profit_50": False,
            "non_profit_10": False,
            "internal": False,
        }

    @property
    def seat_model(self):
        if self.role.billed_seats:
            return Seat
        else:
            return NoBillingSeat

    def assign_seat(self):
        if self.role.billed_seats:
            return Seat.objects.place_member(self)
        raise SeatError(f"{self.role} role does not require a billed seat")

    def assign_no_billed_seat(self):
        if not self.role.billed_seats:
            return NoBillingSeat.objects.create(membership=self)
        raise SeatError(f"{self.role} role requires a billed seat")

    def take_seat(self, invitation=None):
        seat = self.seat_model.objects.place_member(self, invitation)
        if invitation:
            invitation.delete()
        return seat

    def set_color(self):
        used_colors_list = self.customer.members.all().values_list("color", flat=True).filter(color__isnull=False)
        used_colors_counter = Counter(used_colors_list)
        used_colors_dict = {color: used_colors_counter[color] for color in settings.USERS_COLOR_LIST}
        min_color = min(used_colors_dict, key=lambda color: used_colors_dict[color])
        min_colors = [
            color for color in settings.USERS_COLOR_LIST if used_colors_dict[color] == used_colors_dict[min_color]
        ]
        color = random.choice(min_colors)
        self.color = color

    @transaction.atomic
    def convert_to_seat_role(self, destination_role):
        """Convert a no-billing-seat membership to a role that requires a billed seat"""
        if self.role.billed_seats:
            raise SeatError(f"{self} is already on a billed seat role")
        if not destination_role.billed_seats:
            raise SeatError(f"{destination_role} role does not require a billed seat")
        self.role = destination_role
        self.assign_seat()
        no_billing_seat = self.no_billing_seat
        no_billing_seat.membership = None
        no_billing_seat.delete()

    @transaction.atomic
    def convert_to_free_admin(self, assign_no_billed_seat):
        try:
            free_admin_role = Role.objects.get(name=settings.ROLES[settings.FREE_ADMIN])
            if self.role == free_admin_role:
                raise SeatError(f"{self} is already on a no billed seat with Free Admin role")
            self.role = free_admin_role
            if assign_no_billed_seat:
                self.assign_no_billed_seat()
                seat = self.seat
                seat.membership = None
                seat.delete()
        except Role.DoesNotExist:
            raise SeatError("Free admin role does not exists")


class UserInvitation(TimeStampedModel, AbstractBaseInvitation):
    email = models.EmailField(
        unique=False,
        verbose_name=_("e-mail address"),
        max_length=settings.INVITATIONS_EMAIL_MAX_LENGTH,
    )
    customer = models.ForeignKey(
        Customer,
        verbose_name=_("customer"),
        related_name="customer_userinvitations",
        on_delete=models.CASCADE,
    )
    role = models.ForeignKey(Role, verbose_name=_("role"), related_name="+", on_delete=models.CASCADE)
    first_name = models.CharField(_("First Name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    last_name = models.CharField(_("Last Name"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    permission_type = models.CharField(
        verbose_name=_("Permission Type"),
        max_length=settings.TEXT_FIELD_STANDARD_LENGTH,
        default=Membership.PERMISSION_TYPES.full_access,
    )
    settings = models.TextField(_("Settings"), null=True, blank=True)

    class Meta:
        verbose_name = _("user invitation")
        verbose_name_plural = _("user invitations")
        ordering = ("modified",)
        permissions = (("add_edit_remove_user", "Can add/edit/remove users"),)
        unique_together = ("customer", "email")

    def __str__(self):
        return f"invitation {self.pk} on customer {self.customer} for user {self.email}"

    def brand_list(self):
        brand_list = []
        if self.settings:
            invitation_settings = json.loads(self.settings)
            brand_list = invitation_settings.get("brand_list", brand_list)
        return brand_list

    def create_membership(self):
        from beepro_agency_messages.models import Brand, BrandPermission

        email_address = EmailAddress.objects.get(email__iexact=self.email, verified=True, primary=True)
        user = email_address.user

        try:
            membership = Membership.objects.get(customer=self.customer, user=user)
            created = False
        except Membership.DoesNotExist:
            membership = Membership.objects.create(
                customer=self.customer,
                user=user,
                user_status=UserStatus.objects.get(name="active"),
                role=self.role,
                permission_type=self.permission_type,
            )
            created = True

        for brand_id in self.brand_list():
            BrandPermission.objects.get_or_create(brand=Brand.objects.get(pk=brand_id), user_id=user.pk)

        if created:
            return membership

    @classmethod
    def create(cls, email, inviter=None, settings=None, **kwargs):
        key = get_random_string(64).lower()
        instance = cls._default_manager.create(email=email, key=key, inviter=inviter, settings=settings, **kwargs)
        return instance

    def key_expired(self):
        expiration_date = self.sent + datetime.timedelta(days=invitations_settings.INVITATION_EXPIRY)
        return expiration_date <= timezone.now()

    def send_invitation(self, request, **kwargs):
        current_site = kwargs["site"] if "site" in kwargs else Site.objects.get_current()

        invite_url = settings.INVITATION_FRONTEND_BASE_URL + self.key

        context = {
            "invite_url": invite_url,
            "site_name": current_site.name,
            "email": self.email,
            "key": self.key,
            "inviter": self.inviter.first_name + " " + self.inviter.last_name,
            "inviter_email": self.inviter.email_address,
            "customer": self.customer,
        }

        email_template = "invitations/email/email_invitation"
        get_adapter().send_mail(email_template, self.email, context)
        self.sent = timezone.now()
        self.save()

        signals.invite_url_sent.send(
            sender=self.__class__,
            instance=self,
            invite_url_sent=invite_url,
            inviter=self.inviter,
        )

    def reserve_seat(self, seat):
        if seat.is_free:
            seat.invitation = self
            seat.save()
        else:
            raise ValidationError(
                {
                    "seats": _(f"Seat {seat} it's not free"),
                    "code": "ST001",
                }
            )

    def reserve_no_billing_seat(self):
        return NoBillingSeat.objects.create(invitation=self)

    def recreate(self):
        new_invitation_data = {
            "email": self.email,
            "customer": self.customer,
            "role": self.role,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "settings": self.settings,
            "inviter": self.inviter,
            "permission_type": self.permission_type,
        }
        if self.role.billed_seats:
            seat = self.seat
            self.delete()
            seat.refresh_from_db()
            new_invitation = self.create(**new_invitation_data)
            new_invitation.reserve_seat(seat)
        else:
            self.delete()
            new_invitation = self.create(**new_invitation_data)
            new_invitation.reserve_no_billing_seat()
        return new_invitation


class JoinRequest(TimeStampedModel):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="join_requests")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    STATUS = Choices("pending", "rejected")
    status = StatusField()

    class Meta:
        unique_together = ["customer", "user"]

    def clean(self):
        if self.customer.members.filter(user=self.user).exists():
            raise ValidationError("User is already a member of this customer")
        if not Customer.objects.joinable(self.user).filter(pk=self.customer.pk).exists():
            raise ValidationError("User cannot join this customer")


def populate_plan_log():
    """Populate plan log with initial data."""
    return [{"plan": Subscription.PLAN_DEFAULT, "datetime": timezone.now().isoformat()}]


def populate_status_log():
    """Populate status log with initial data."""
    return [{"status": Subscription.STATUS_DEFAULT, "datetime": timezone.now().isoformat()}]


class Subscription(TimeStampedModel):
    """A Subscription."""

    PLAN_UNDEFINED = "undefined"
    PLAN_FREE = "beepro_free"
    PLAN_FREELANCER_ANNUAL = "beepro_freelancer_annual"
    PLAN_FREELANCER = "beepro_freelancer"
    PLAN_TEAM_ANNUAL = "beepro_team_annual"
    PLAN_TEAM = "beepro_team"
    PLAN_AGENCY_ANNUAL = "beepro_agency_annual"
    PLAN_AGENCY = "beepro_agency"
    PLAN_ENTERPRISE_ANNUAL = "beepro_enterprise_annual"
    PLAN_ENTERPRISE = "beepro_enterprise"

    PLANS = [
        (PLAN_UNDEFINED, _("undefined")),
        (PLAN_FREE, _("beepro_free")),
        (PLAN_FREELANCER_ANNUAL, _("beepro freelancer annual")),
        (PLAN_FREELANCER, _("beepro freelancer")),
        (PLAN_TEAM_ANNUAL, _("beepro team annual")),
        (PLAN_TEAM, _("beepro team")),
        (PLAN_AGENCY_ANNUAL, _("beepro agency annual")),
        (PLAN_AGENCY, _("beepro agency")),
        (PLAN_ENTERPRISE_ANNUAL, _("beepro enterprise annual")),
        (PLAN_ENTERPRISE, _("beepro enterprise")),
    ]

    STATUS_UNDEFINED = "undefined"
    STATUS_TRIALING = "trialing"
    STATUS_TRIAL_ENDED = "trial_ended"
    STATUS_ACTIVE = "active"
    STATUS_PAUSED = "paused"
    STATUS_SUSPENDED = "suspended"
    STATUS_CANCELLED = "cancelled"

    STATUSES = [
        (STATUS_UNDEFINED, _("undefined")),
        (STATUS_TRIALING, _("trialing")),
        (STATUS_TRIAL_ENDED, _("trial_ended")),
        (STATUS_ACTIVE, _("active")),
        (STATUS_PAUSED, _("paused")),
        (STATUS_SUSPENDED, _("suspended")),
        (STATUS_CANCELLED, _("cancelled")),
    ]

    # billing -> application mapping
    PLAN_NAMES_MAP = {
        PLAN_FREE: settings.FREE,
        PLAN_FREELANCER: settings.FREELANCER,
        PLAN_FREELANCER_ANNUAL: settings.FREELANCER,
        PLAN_TEAM: settings.TEAM,
        PLAN_TEAM_ANNUAL: settings.TEAM,
        PLAN_AGENCY: settings.AGENCY,
        PLAN_AGENCY_ANNUAL: settings.AGENCY,
        PLAN_ENTERPRISE: settings.ENTERPRISE,
        PLAN_ENTERPRISE_ANNUAL: settings.ENTERPRISE,
    }

    PLANS_ORDER = [
        PLAN_FREE,
        PLAN_FREELANCER,
        PLAN_FREELANCER_ANNUAL,
        PLAN_TEAM,
        PLAN_TEAM_ANNUAL,
        PLAN_AGENCY,
        PLAN_AGENCY_ANNUAL,
        PLAN_ENTERPRISE,
        PLAN_ENTERPRISE_ANNUAL,
    ]

    PLAN_UPGRADE = 1
    PLAN_SAME = 0
    PLAN_DOWNGRADE = -1

    STATUS_DEFAULT = STATUS_ACTIVE
    PLAN_DEFAULT = PLAN_FREE

    TOKENS_PACKAGES = Choices(
        "unlimited",
    )

    customer = models.OneToOneField(
        Customer,
        verbose_name=_("customer"),
        related_name="subscription",
        on_delete=models.CASCADE,
    )
    subscription_id = models.CharField(
        verbose_name=_("subscription"),
        max_length=settings.TEXT_FIELD_STANDARD_LENGTH,
        null=True,
        blank=True,
    )
    offline = models.BooleanField(default=False)
    max_additional_users = models.IntegerField(default=settings.SUBSCRIPTION_MAX_ADDITIONAL_USERS)
    max_no_billing_seats = models.IntegerField(default=settings.SUBSCRIPTION_MAX_GUESTS)
    max_single_brand_users = models.IntegerField(default=settings.SUBSCRIPTION_MAX_SINGLE_BRAND_USERS)
    billing_data = JSONField(default=dict, encoder=DjangoJSONEncoder, blank=True)
    billing_data_last_updated = models.DateTimeField(_("last updated"), editable=False, null=True)
    plan = models.CharField(_("plan"), max_length=100, choices=PLANS, default=PLAN_DEFAULT)
    plan_log = JSONField(default=list, encoder=DjangoJSONEncoder, blank=True)
    status = models.CharField(_("status"), max_length=50, choices=STATUSES, default=STATUS_DEFAULT)
    status_log = JSONField(default=list, encoder=DjangoJSONEncoder, blank=True)
    assets_disabled = models.BooleanField(verbose_name=_("Assets disabled"), default=False)
    upcoming_changes = JSONField(default=dict, encoder=DjangoJSONEncoder, blank=True)
    migration_changes = JSONField(default=dict, encoder=DjangoJSONEncoder, blank=True)
    account_number = models.CharField(max_length=settings.TEXT_FIELD_STANDARD_LENGTH, null=True, blank=True)
    ai_tokens = models.IntegerField(null=True, blank=True)
    non_profit_discount_eligible = models.BooleanField(default=False)
    tokens_package = models.CharField(max_length=50, choices=TOKENS_PACKAGES, null=True, blank=True)

    objects: SubscriptionManager = SubscriptionManager()
    living_objects: LivingSubscriptionManager = LivingSubscriptionManager()
    trials: TrialSubscriptionManager = TrialSubscriptionManager()
    cron_jobs_subs: CronJobSubscriptionManager = CronJobSubscriptionManager()

    class Meta:
        verbose_name = _("subscription")
        verbose_name_plural = _("subscription")
        ordering = ("modified",)
        permissions = (("manage_subscription", "Can manage subscription"),)

    def __str__(self):
        return f"ID: {self.id} | SUB_ID: {self.subscription_id}"

    def save(self, *args, **kwargs):
        created = self.pk is None
        super().save(*args, **kwargs)

        if not created and self.offline:
            self.update_seats()

    @property
    def has_valid_subscription_id(self):
        return self.subscription_id is not None and re.match(r"^(A-S)?(\d){8}$", self.subscription_id) is not None

    @property
    def subscription_identifier(self):
        return f"{settings.SUBSCRIPTION_ID_PREFIX}-{self.id}"

    @property
    def crm_id(self):
        return self.customer.account_id

    @property
    def is_annual(self):
        return "_annual" in self.plan

    @property
    def interval(self):
        return "Year" if self.is_annual else "Month"

    @staticmethod
    def get_minimum_update_threshold_seconds():
        """Return a datetime in the past subtracting the value in seconds specified in the settings."""
        return timezone.now() - datetime.timedelta(seconds=settings.SUBSCRIPTION_BILLING_DATA_UPDATE_FREQUENCY)

    def can_update_billing_data(self):
        """
        Return whether billing data can be updated again.

        Force update if subscription was just created.
        """
        time_delta = (
            self.billing_data_last_updated
            if self.billing_data_last_updated
            else self.get_minimum_update_threshold_seconds()
        )
        return (timezone.now() - time_delta).seconds >= settings.SUBSCRIPTION_BILLING_DATA_UPDATE_FREQUENCY

    def update_billing_data(self, update_plan=False, update_status=False):
        """Update billing data."""
        if self.switch_plan_in_progress:
            return False
        billing_account = BillingAccount(self)
        subscription_data = billing_account.get_billing_data()
        if not subscription_data:
            return False
        else:
            self.billing_data = subscription_data
            self.billing_data_last_updated = timezone.now()
            if update_plan:
                self.plan = self.billing_data["plan"]
            if update_status:
                self.status = self.billing_data["status"]
            if account_number := self.billing_data.get("extra_info", {}).get("account_number"):
                self.account_number = account_number
            self.save()
            return True

    @classmethod
    def bulk_update_billing_data(
        cls,
        queryset=None,
        update_plans=False,
        update_statuses=False,
        update_plans_and_statuses_for_blocking_statuses=True,
        batch_size=None,
    ):
        """Bulk update billing data."""
        subscriptions_to_update = list()
        subscriptions_not_found = list()
        fields_to_update_from_modifiers = [
            "billing_data",
            "billing_data_last_updated",
            "plan",
            "plan_log",
            "status",
            "status_log",
        ]
        subscriptions = queryset or Subscription.objects.all().exclude(
            Q(
                status__in=(
                    cls.STATUS_SUSPENDED,
                    cls.STATUS_CANCELLED,
                    cls.STATUS_TRIAL_ENDED,
                    cls.STATUS_UNDEFINED,
                )
            )
            | Q(plan__in=(cls.PLAN_FREE))
        )
        total_subscriptions = len(subscriptions)
        batch_size = batch_size or total_subscriptions
        success_counter = 0
        fail_counter = 0
        last_success_saved = -1
        last_fail_saved = -1
        for i, subscription in enumerate(subscriptions):
            # Fetch
            billing_account = BillingAccount(subscription)
            remote_billing_data, billing_data_status = billing_account.get_billing_data(response_only=False)
            former_plan = subscription.plan  # noqa
            former_status = subscription.status  # noqa
            if remote_billing_data and billing_data_status == 200:
                success_counter += 1
                remote_billing_data = remote_billing_data.json()
                subscription.billing_data = remote_billing_data
                subscription.billing_data_last_updated = timezone.now()
                update_statuses_for_blocking_statuses_flag = (
                    True
                    if update_plans_and_statuses_for_blocking_statuses
                    and remote_billing_data["status"]
                    in (
                        cls.STATUS_SUSPENDED,
                        cls.STATUS_CANCELLED,
                        cls.STATUS_TRIAL_ENDED,
                        cls.STATUS_UNDEFINED,
                    )
                    else False
                )
                plan_has_changed = update_plans and subscription.plan != subscription.billing_data["plan"]
                status_has_changed = update_statuses or update_statuses_for_blocking_statuses_flag
                if plan_has_changed:
                    subscription.plan = subscription.billing_data["plan"]
                    subscription.update_plan_log()
                if status_has_changed:
                    subscription.status = subscription.billing_data["status"]
                    subscription.update_status_log()
                if plan_has_changed or status_has_changed:
                    subscription.send_data_to_zapier()
                    async_wrapper(
                        update_AC_contact,
                        subscription.customer,
                        group="ActiveCampaign sync",
                        save=False,
                    )
                subscriptions_to_update.append(subscription)
            else:
                # Log also if you failed, for forced updates
                fail_counter += 1
                if billing_data_status == 404:
                    subscription.billing_data = {}
                    subscription.billing_data_last_updated = timezone.now()
                    if update_plans and subscription.plan != cls.PLAN_UNDEFINED:
                        subscription.plan = cls.PLAN_UNDEFINED
                        subscription.update_plan_log()
                    if update_statuses:
                        subscription.status = cls.STATUS_UNDEFINED
                        subscription.update_status_log()
                subscriptions_not_found.append(subscription)
            print(
                f"[{success_counter}|{fail_counter}|{i + 1}/{total_subscriptions}] "
                f"Subscription {subscription.subscription_id} "
                f'{"FOUND" if remote_billing_data else "MISSING"} | OLD: {former_plan}, {former_status}'
                f'{f" | NEW: {subscription.plan}, {subscription.status}"}'
            )

            # Save batched
            is_regular_success_batch = ((success_counter % batch_size) == 0) and success_counter > 0
            is_remainder_batch = (success_counter + fail_counter) == total_subscriptions
            is_regular_fail_batch = ((fail_counter % batch_size) == 0) and fail_counter > 0
            if is_regular_success_batch or is_remainder_batch:
                success_batch_start = (
                    (success_counter - batch_size)
                    if is_regular_success_batch
                    else success_counter - (success_counter % batch_size)
                )
                if success_batch_start > last_success_saved and success_counter > 0:
                    Subscription.objects.bulk_update(
                        subscriptions_to_update[success_batch_start:],
                        fields_to_update_from_modifiers,
                    )
                    last_success_saved = success_batch_start
                    print(
                        f"      Saved SUCCESS batch on DB "
                        f"(from {success_batch_start + 1} to {len(subscriptions_to_update)}"
                        f'{" FINAL" if is_remainder_batch else ""}'
                        f")"
                    )
            if is_regular_fail_batch or is_remainder_batch:
                fail_batch_start = (
                    (fail_counter - batch_size)
                    if is_regular_fail_batch
                    else fail_counter - (fail_counter % batch_size)
                )
                if fail_batch_start > last_fail_saved and fail_counter > 0:
                    Subscription.objects.bulk_update(
                        subscriptions_not_found[fail_batch_start:],
                        fields_to_update_from_modifiers,
                    )
                    last_fail_saved = fail_batch_start
                    print(
                        f"      Saved FAIL batch on DB "
                        f"(from {fail_batch_start + 1} to {len(subscriptions_not_found)}"
                        f'{" FINAL" if is_remainder_batch else ""}'
                        f")"
                    )
        return subscriptions_to_update, subscriptions_not_found

    def update_plan_log(self):
        """Update plan log."""
        self.plan_log.append({"plan": self.plan, "datetime": timezone.now().isoformat()})

    def update_status_log(self):
        """Update status log."""
        self.status_log.append({"status": self.status, "datetime": timezone.now().isoformat()})

    def send_disable_assets_email(self):
        user = self.customer.owner
        if user:
            context = {
                "email": user.email,
                "days_perm_delete": settings.SUBSCRIPTION_TO_CANCEL_SERVICE_SUSPENDED,
            }
            get_adapter().send_mail("account/email/email_disable_assets", user.email, context)

    def enable_assets(self):
        t_id = async_task(
            "beepro_agency_users.utils.core.enable_assets_async",
            self.customer,
            group="Customer Assets",
        )
        self.update_assets_flag(False)
        return t_id

    @property
    def included_traffic(self) -> int:
        """CDN Traffic included in the subscription plan"""
        included_traffic = settings.RESTRICTIONS["IncludedTrafficMb"].get(self.application_plan)
        return included_traffic

    included_traffic.fget.short_description = "CDN Traffic included in the subscription plan"  # type: ignore

    def cleanup_brand_permissions(self):
        from beepro_agency_messages.models import BrandPermission

        BrandPermission.objects.filter(brand__in=self.customer.brands).delete()

    def update_brand_permissions(self):
        for brand in self.customer.brands:
            brand.populate()

    @property
    def included_brands_number(self) -> int:
        """Brands included in the subscription plan"""
        included_brands = settings.RESTRICTIONS["Brand"].get(self.application_plan)
        return included_brands

    @property
    def included_projects_number(self) -> int:
        """Projects included in the subscription plan"""
        included_projects = settings.RESTRICTIONS["Project"].get(self.application_plan)
        return included_projects

    @property
    def total_seats_number(self) -> int:
        """Total available seats number on database"""
        return self.seats.all().count()

    @property
    def included_seats_number(self) -> int:
        """Seats included in the subscription plan"""
        return settings.RESTRICTIONS["IncludedSeats"].get(self.application_plan)

    included_seats_number.fget.short_description = "Included seats number in the subscription plan"  # type: ignore

    @property
    def additional_seats_number(self) -> int:
        """Additional seats on database"""
        if self.offline:
            return self.max_additional_users
        return self.total_seats_number - self.included_seats_number

    @property
    def required_seats_number(self) -> int:
        """
        Number of seats required to accomodate all the already existing members and invitations
        """
        if self.offline:
            return self.included_seats_number + self.max_additional_users
        invitations = UserInvitation.objects.filter(customer=self.customer, role__billed_seats=True, accepted=False)
        return self.customer.members.filter(role__billed_seats=True).count() + invitations.count()

    @property
    def occupied_seats_number(self) -> int:
        """Occupied seats number"""
        return self.seats.occupied().count()

    @property
    def free_seats_number(self) -> int:
        """Free seats number (aka: with no membership or invitation)"""
        return self.seats.free().count()

    free_seats_number.fget.short_description = "Free seats number (no membership or invitation)"  # type: ignore

    @property
    def reserved_seats_number(self) -> int:
        """Reserved seats number"""
        return self.seats.reserved().count()

    @property
    def free_active_seat_number(self) -> int:
        """Free active seats number (aka: with no membership or invitation and not in pending cancellation)"""
        return self.seats.free().active().count()

    @property
    def pending_cancellation_seats_number(self) -> int:
        """Pending_cancellation seats number"""
        return self.seats.pending_cancellation().count()

    @property
    def max_removable_seats(self):
        """Maximum number of seats that can be deleted"""
        removable_additional = self.additional_seats_number - self.pending_cancellation_seats_number
        return (
            removable_additional
            if removable_additional < self.free_active_seat_number
            else self.free_active_seat_number
        )

    def destination_seats_number(self, to_product_handle) -> list[int]:
        plan_name = self.PLAN_NAMES_MAP.get(to_product_handle)
        included_seats = settings.RESTRICTIONS["IncludedSeats"].get(plan_name)
        if self.switch_plan_direction(to_product_handle) == Subscription.PLAN_DOWNGRADE:
            extra_seats = (
                self.total_seats_number
                - self.free_active_seat_number
                - included_seats
                - self.pending_cancellation_seats_number
            )
        elif self.application_plan == settings.FREE:
            extra_seats = self.total_seats_number + self.no_billing_seats_number - included_seats
        else:
            extra_seats = self.total_seats_number - included_seats - self.pending_cancellation_seats_number
        additional_seats = max(0, extra_seats)
        return [included_seats, additional_seats]

    def add_seats(self, quantity: int):
        """Update Billing with new additional seats number and the create them on db"""
        #  TODO Move to billing client
        if self.offline:
            raise OfflineSubscriptionException
        updated_quantity = self.additional_seats_number + quantity
        billing_account = BillingAccount(self)
        response, status_code = billing_account.handle_seats(operation="add", quantity=updated_quantity)
        if status_code == status.HTTP_200_OK:
            return self.create_seats(quantity)
        else:
            raise SubscriptionException

    def remove_seat(self, seat):
        """Remove a single seat: Update Billing with new additional seats number and set expiration_date on db"""
        if self.offline:
            raise OfflineSubscriptionException
        if not seat.is_free:
            raise ProtectedError(f"Seat {seat.pk} it's not free and can't be deleted", self)
        if not self.additional_seats_number:
            raise ProtectedError(
                f"Subscription includes {self.included_seats_number} seats that can't be deleted",
                self,
            )
        updated_quantity = self.additional_seats_number - 1
        billing_account = BillingAccount(self)
        response, status_code = billing_account.handle_seats(operation="remove", quantity=updated_quantity)
        if status_code == status.HTTP_200_OK:
            expiration_date = self.billing_data.get("next_billing_date")
            seat.expiration_date = expiration_date
            seat.save()
            return seat
        else:
            raise SubscriptionException

    def remove_free_seats(self, quantity: int):
        """Remove multiple free seats: Update Billing with new additional seats number and set expiration_date on db"""
        updated_quantity = self.additional_seats_number - quantity
        if updated_quantity < 0:
            raise ProtectedError(
                f"Subscription includes {self.included_seats_number} seats that can't be deleted",
                self,
            )
        billing_account = BillingAccount(self)
        response, status_code = billing_account.handle_seats(operation="remove", quantity=updated_quantity)
        removed_seats = []
        if status_code == status.HTTP_200_OK:
            expiration_date = self.billing_data.get("next_billing_date")
            for i in range(quantity):
                seat = self.seats.free().active().first()
                seat.expiration_date = expiration_date
                seat.save()
                removed_seats.append(seat)
        return removed_seats

    def create_initial_seats(self):
        """Creates initial included seats - based on plan - on database"""
        self.create_seats(self.included_seats_number)

    def create_seats(self, seats_number: int):
        added_seats = (Seat(subscription=self) for seat in range(seats_number))
        return Seat.objects.bulk_create(added_seats)

    @property
    def spare_members(self):
        """Subscription members with no seat"""
        return self.customer.members.filter(seat__isnull=True, role__billed_seats=True)

    def place_spare_members(self):
        """Assign a seat to spare members"""
        for member in self.spare_members:
            member.assign_seat()
        return self.spare_members

    def place_owner(self):
        """Assign a seat to the owner if is spare"""
        try:
            owner_membership = self.spare_members.get(role__name="Owner")
        except Membership.DoesNotExist:
            return None
        return owner_membership.assign_seat()

    def update_seats(self) -> int:
        """
        Adjust seats on db to fit required seats, adding them where necessary.
        WARNING: No comunication with billing.
        """
        required = (
            self.required_seats_number
            if (self.included_seats_number < self.required_seats_number)
            else self.included_seats_number
        )
        difference = required - self.total_seats_number
        if difference > 0:
            self.create_seats(difference)
        return difference

    @staticmethod
    def send_data_to_zapier_async(subscription):
        data = subscription.get_data_for_zapier()
        if data["user"]["user_email"]:
            response = ZapierClient().send_subscription_crud(data, subscription.id, old=False)
            return response

    def send_data_to_zapier(self):
        async_task(Subscription.send_data_to_zapier_async, self, group="Zapier", save=False)

    def delete_data_from_mailup_list(self):
        data = {"action": "delete", "user": {"user_email": self.customer.owner.email}}
        response = ZapierClient().send_subscription_crud(data, self.id, old=False)
        return response

    def get_data_for_zapier(self, billing_data_required=True):
        customer = self.customer
        user = customer.owner
        subscription_id = self.subscription_id

        extra_params = user.extra_params_dict if user else {}
        metadata = extra_params.get("Metadata", [])
        metadata_dict = {item.get("name", ""): item.get("value", "") for item in metadata}

        if billing_data_required:
            billing_account = BillingAccount(self)
            billing_data = billing_account.get_billing_data()
            billing_address = billing_data.get("billing_address", {}) if billing_data else {}
        else:
            billing_address = {}

        plan_name = settings.PENDO_PLAN_NAMES.get(self.plan, "")
        status_name = settings.STATUS_ZUORA_NAMES.get(self.status, "")

        return {
            "unique_key": self.crm_id,
            "action": "add_or_update",
            "user": {
                "user_company": customer.name,
                "user_role": "Owner",
                "user_email": user.email if user else "",
                "user_first_name": user.first_name if user else "",
                "user_last_name": user.last_name if user else "",
            },
            "subscription": {
                "id": subscription_id,
                "product": "Bee Pro",
                "plan": plan_name,
                "interval": self.interval,
                "status": status_name,
                "start_date": self.created.strftime("%Y-%m-%d"),
            },
            "billing_info": {
                "first_name": billing_address.get("first_name", ""),
                "last_name": billing_address.get("last_name", ""),
                "address_1": billing_address.get("address_1", ""),
                "address_2": billing_address.get("address_2", ""),
                "city": billing_address.get("city", ""),
                "country": billing_address.get("country", ""),
                "state": billing_address.get("state", ""),
                "postal_code": billing_address.get("zip_code", ""),
                "email": billing_address.get("work_email", ""),
                "phone": billing_address.get("work_phone", ""),
                "company": billing_address.get("company", ""),
            },
            "tracking": metadata_dict,
        }

    @staticmethod
    def send_data_to_old_zapier_async(subscription):
        data = subscription._get_data_for_old_zapier()
        response = ZapierClient().send_subscription_crud(data, subscription.id, old=True)
        return response

    def send_data_to_old_zapier(self):
        async_task(
            Subscription.send_data_to_old_zapier_async,
            self,
            group="Old Zapier",
            save=False,
        )

    def _get_data_for_old_zapier(self):
        customer = self.customer
        user = customer.owner

        extra_params = user.extra_params_dict if user else {}
        metadata = extra_params.get("Metadata", [])
        metadata_dict = {item.get("name", ""): item.get("value", "") for item in metadata}

        plan_name = settings.PENDO_PLAN_NAMES.get(self.plan, "")
        status_name = settings.STATUS_ZUORA_NAMES.get(self.status, "")

        next_billing_date = self.billing_data.get("next_billing_date", "")
        if isinstance(next_billing_date, datetime.date):
            next_billing_date = next_billing_date.strftime("%Y-%m-%d")

        return {
            "unique_key": self.crm_id,
            "account": {"name": customer.name},
            "subscription": {
                "id": self.subscription_id,
                "product": "Bee Pro",
                "plan": plan_name,
                "interval": self.interval,
                "status": status_name,
                "start_date": self.created.strftime("%Y-%m-%d"),
            },
            "customer": {
                "first_name": user.first_name if user else "",
                "last_name": user.last_name if user else "",
                "address_1": "",
                "address_2": "",
                "city": "",
                "country": "",
                "state": "",
                "postal_code": "",
                "email": user.email if user else "",
                "phone": "",
            },
            "extra": {
                "coupon_code": "",
                "referral_code": "",
                "product_rate_plan": {"id": "8a288b296d4dac90016d6f6a5d1334c6"},
                "rate_plan_charge": {
                    "name": "Free Trial",
                    "model": "Flat Fee Pricing",
                    "start_date": self.created.strftime("%Y-%m-%d"),
                    "end_date": next_billing_date,
                    "mrr": 0,
                },
            },
            "tracking": metadata_dict,
        }

    def last_status_log_date_before_than(self, ref_date):
        if self.status_log:
            last_status = self.status_log[-1]
            if last_status["status"] != self.status:
                self.update_status_log()
                self.save()
                return False
            else:
                return timezone.datetime.fromisoformat(last_status["datetime"]) < ref_date
        else:
            self.update_status_log()
            self.save()
            return False

    def last_status_log_date_equal_to(self, ref_date):
        last_status_date_str = self._get_last_status_log_datetime()
        if last_status_date_str:
            ref_date_str = ref_date.strftime("%Y-%m-%d")
            return last_status_date_str == ref_date_str
        return False

    def last_status_log_date_in_range(self, from_date, to_date):
        last_status_date_str = self._get_last_status_log_datetime()
        if last_status_date_str:
            from_date_str = from_date.strftime("%Y-%m-%d")
            to_date_str = to_date.strftime("%Y-%m-%d")
            return to_date_str >= last_status_date_str >= from_date_str
        return False

    def _get_last_status_log_datetime(self):
        if self.status_log:
            last_status = self.status_log[-1]
            if last_status["status"] == self.status:
                return timezone.datetime.fromisoformat(last_status["datetime"]).strftime("%Y-%m-%d")
        return None

    def create_partnerstack_account(self):
        customer = self.customer
        user = customer.owner

        metadata = user.extra_params_dict.get("Metadata", [])
        ps_keys = [item for item in metadata if item.get("name", "") == "partnerstack_gspk" and item.get("value")]

        if ps_keys:
            partnerstack_gspk = ps_keys[0].get("value", "")
            ps_data = {
                "partner_key": partnerstack_gspk,
                "email": user.email,
                "key": self.crm_id,
                "name": customer.name,
            }
            if not PartnerstackClient().create_customer(ps_data):
                raise SubscriptionException({})

    @property
    def is_dunning(self):
        return self.billing_data.get("dunning_status", "") == settings.BILLING_DATA_DUNNING_STATUS["UNPAID"]

    @property
    def dunning_status(self):
        return self.billing_data.get("dunning_status", "")

    def update_assets_flag(self, flag):
        self.assets_disabled = flag

    def switch_plan_direction(self, product_handle) -> int:
        current = Subscription.PLANS_ORDER.index(self.plan)
        destination = Subscription.PLANS_ORDER.index(product_handle)
        return (destination > current) - (destination < current)

    @property
    def switch_plan_cache_key(self):
        return f"subscription-plan-switch-{self.id}"

    @property
    def switch_plan_in_progress(self):
        return cache.get(self.switch_plan_cache_key)

    @property
    def next_billing_date(self):
        return self.billing_data.get("next_billing_date", "")

    @property
    def billing_period(self) -> tuple[datetime.datetime, datetime.datetime]:
        if self.plan == Subscription.PLAN_FREE:
            today = datetime.datetime.now(datetime.timezone.utc)
            first_day_of_month = datetime.datetime(today.year, today.month, 1, tzinfo=today.tzinfo)
            last_day_of_month = first_day_of_month + relativedelta(months=1) - relativedelta(microseconds=1)
            last_switch_plan_date = datetime.datetime.fromisoformat(self.plan_log[-1]["datetime"])
            return max(first_day_of_month, last_switch_plan_date), last_day_of_month
        raise NotImplementedError("Paid subscriptions not implemented yet")

    def set_trial_end_date(self, date: datetime.date):
        if self.status not in (
            Subscription.STATUS_TRIALING,
            Subscription.STATUS_TRIAL_ENDED,
        ):
            raise SubscriptionException()
        upcoming_changes = {"date": date, "status": self.STATUS_TRIAL_ENDED}
        billing_data = {"status": "trialing", "next_billing_date": date}
        self.upcoming_changes = upcoming_changes
        self.billing_data = billing_data
        self.status = Subscription.STATUS_TRIALING

    def set_switch_plan_date(self, date: datetime.date, destination_plan: str):
        upcoming_changes = {"date": date, "plan": destination_plan}
        self.upcoming_changes = upcoming_changes

    def set_upcoming_cancellation(self, date: datetime.date | None = None):
        self.upcoming_changes["status"] = Subscription.STATUS_CANCELLED
        self.billing_data["pending_suspension"] = True
        if date:
            self.upcoming_changes["date"] = date

    def trigger_trialfeature_upgraded(self):
        for trial_feature in self.trialfeature_set.all():
            try:
                trial_feature._transition_to_upgraded()
                trial_feature.save()
            except InvalidTransition:
                pass

    @property
    def application_plan(self):
        return self.PLAN_NAMES_MAP.get(self.plan)

    @property
    def is_trial(self):
        return self.status in (
            Subscription.STATUS_TRIALING,
            Subscription.STATUS_TRIAL_ENDED,
        )

    @property
    def is_active(self):
        return self.status == Subscription.STATUS_ACTIVE

    @property
    def pending_downgrade(self) -> bool:
        return bool(self.upcoming_changes.get("plan")) or bool(self.switch_plan_in_progress)

    @property
    def pending_tokens_deletion(self) -> bool:
        return "remove" in self.upcoming_changes.get("tokens_package", "")

    def switch_plan_info(self, date: datetime.date) -> dict:
        return {
            "can_downgrade": date.isoformat() != self.next_billing_date,
            "downgrade_pending": self.pending_downgrade,
        }

    def send_downgrade_email(self):
        user = self.customer.owner
        if user:
            context = {
                "email": user.email,
                "plan_name": self.PLAN_NAMES_MAP.get(self.upcoming_changes.get("plan")),
            }
            get_adapter().send_mail("account/plan_downgrade", user.email, context)

    @property
    def no_billing_seats_number(self):
        return self.no_billing_seats.all().count()

    @property
    def reserved_no_billing_seats_number(self):
        return self.no_billing_seats.reserved().count()

    @property
    def cmrr(self):
        return self.billing_data.get("extra_info", {}).get("metrics", {}).get("contractedMrr", "")

    @property
    def max_no_billing_users(self):
        if self.offline:
            return self.max_no_billing_seats
        return settings.RESTRICTIONS["MaxNoBillingSeat"].get(self.application_plan)

    @property
    def upcoming_cancellation_date(self):
        if self.upcoming_changes.get("status") != Subscription.STATUS_CANCELLED:
            return None
        return self.upcoming_changes.get("date")

    @property
    def trial_done(self) -> bool:
        return self.subscription_id is not None or any(entry["status"] == "trialing" for entry in self.status_log)

    @property
    def billing_plan_mismatch(self):
        plan_on_billing = self.billing_data.get("plan")
        return not self.plan == plan_on_billing

    @property
    def has_unpaid_cdn(self):
        return self.customer.unpaid_cdn.exists()

    def downgraded_to_free_this_month(self, today):
        if len(self.plan_log) == 1:
            return False

        last_entry = self.plan_log[-1]
        second_last_entry = self.plan_log[-2]

        last_entry_ym = timezone.datetime.fromisoformat(last_entry["datetime"]).strftime("%Y-%m")
        second_last_entry_ym = timezone.datetime.fromisoformat(second_last_entry["datetime"]).strftime("%Y-%m")

        current_ym = today.strftime("%Y-%m")
        free_this_month = last_entry_ym == current_ym and last_entry["plan"] == Subscription.PLAN_FREE
        previously_not = second_last_entry_ym != current_ym and second_last_entry["plan"] != Subscription.PLAN_FREE

        return free_this_month and previously_not

    @property
    def has_unlimited_tokens(self):
        return self.tokens_package == self.TOKENS_PACKAGES.unlimited

    @property
    def ai_tokens_limit(self):
        if self.application_plan == settings.ENTERPRISE and self.ai_tokens is not None:
            return self.ai_tokens
        return settings.RESTRICTIONS["AiTokens"][self.application_plan]

    def get_next_token_limits(self, tokens_package):
        next_tokens_limit = -1 if tokens_package == self.TOKENS_PACKAGES.unlimited else self.ai_tokens_limit
        next_words_limit = convert_tokens_to_words(next_tokens_limit)
        return {
            "next_tokens_limit": next_tokens_limit,
            "next_words_limit": next_words_limit,
        }


class Seat(TimeStampedModel):
    """
    This model defines a Seat entity, that can be associated with a membership or an invitation of a given
    subscription
    """

    STATUS = Choices("active", "pending-cancellation")

    status = StatusField()
    subscription = models.ForeignKey(
        Subscription,
        verbose_name=_("subscription"),
        related_name="seats",
        on_delete=models.CASCADE,
    )
    invitation = models.OneToOneField(
        UserInvitation,
        verbose_name=_("invitation"),
        related_name="seat",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    membership = models.OneToOneField(
        Membership,
        verbose_name=_("membership"),
        related_name="seat",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    expiration_date = models.DateField(_("expiration date"), null=True, blank=True)

    objects = SeatManager()

    class Meta:
        verbose_name = _("seat")
        verbose_name_plural = _("seats")
        ordering = ("modified",)
        permissions = (("manage_seat", "Can manage seat"),)

    def __str__(self):
        return f"Seat {self.id} in Subscription {self.subscription.id}"

    def save(self, *args, **kwargs):
        """
        Force subscription and status if possible and validate role
        """
        if self.role and not self.role.billed_seats:
            raise SeatError(f"Role {self.role} does not requires a billed seat")
        if self.expiration_date:
            self.status = "pending-cancellation"
        if self.membership:
            self.subscription = self.membership.customer.subscription
        elif self.invitation:
            self.subscription = self.invitation.customer.subscription
        super().save(*args, **kwargs)

    def clean(self):  # pragma: no cover
        """Protect the edit of the owner seat in django-admin"""
        if self.pk:
            old_seat = Seat.objects.get(pk=self.pk)
            if old_seat.is_owner_seat:
                raise ValidationError("Owner Seat can't be edited")

    def delete(self, *args, **kwargs):
        """
        Protects seat from deletion if it's not free or if it's an included seat
        """
        if not self.is_free:
            raise ProtectedError(f"Seat {self.pk} it's not free and can't be deleted", self)
        seats = self.count_seats(self.subscription)
        if seats <= self.subscription.included_seats_number:
            raise ProtectedError(
                f"Subscription includes {self.subscription.included_seats_number} seat(s) that can't be deleted",
                self,
            )
        return super().delete(*args, **kwargs)

    @classmethod
    def count_seats(cls, subscription) -> int:
        """Count all seats of a give subscription"""
        seats = cls.objects.filter(subscription=subscription)
        return seats.count()

    @property
    def is_free(self) -> bool:
        """Returns True if no membership or invitation is associated with the seat"""
        return not (self.membership or self.invitation)

    @property
    def is_owner_seat(self) -> bool:
        """Return True if an owner membership is associated with the seat"""
        try:
            role = self.membership.role
        except AttributeError:
            return False
        return role.name == "Owner"

    def free_up(self) -> bool:
        """
        Free a seat by removing and deleting the associate membership and invitation, if it's not the owner one
        """
        if self.is_owner_seat:
            return False
        if self.membership:
            self.membership.delete()
            self.membership = None  # must do this due to SoftDelete on Membership
        if self.invitation:
            self.invitation.delete()
            self.invitation = None
        self.save()
        return True

    @property
    def invitation_expired(self) -> bool:
        """Return True if the invitation associated with the seat is expired"""
        if self.invitation:
            return self.invitation.key_expired()
        return False

    @property
    def user(self):
        """Returns the user of the associated membership, if any"""
        try:
            user = self.membership.user
        except AttributeError:
            user = None
        return user

    @property
    def customer(self):
        """Returns the customer of the associated subscription"""
        return self.subscription.customer

    @property
    def role(self):
        if self.membership:
            return self.membership.role
        if self.invitation:
            return self.invitation.role
        return None


class NoBillingSeat(TimeStampedModel):
    subscription = models.ForeignKey(
        Subscription,
        verbose_name=_("subscription"),
        related_name="no_billing_seats",
        on_delete=models.CASCADE,
    )
    invitation = models.OneToOneField(
        UserInvitation,
        verbose_name=_("invitation"),
        related_name="no_billing_seat",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    membership = models.OneToOneField(
        Membership,
        verbose_name=_("membership"),
        related_name="no_billing_seat",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )

    objects = NoBillingSeatManager()

    class Meta:
        verbose_name = _("no-billing-seat")
        verbose_name_plural = _("no-billing-seats")
        ordering = ("modified",)
        permissions = (("manage_no_billing_seat", "Can manage no billing seat"),)

    def __str__(self):
        return f"No Billing Seat {self.id} in Subscription {self.subscription.id}"

    def save(self, *args, **kwargs):
        """
        Raise errors if empty or wrong role
        """
        if self.role and self.role.billed_seats:
            raise SeatError(f"Role {self.role} requires a billed seat")
        if not self.membership and not self.invitation:
            raise SeatError("NoBillingSeat can't be empty")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.membership:
            self.membership.delete()
        if self.invitation:
            self.invitation.delete()
        return super().delete(*args, **kwargs)

    @property
    def user(self):
        """Returns the user of the associated membership, if any"""
        try:
            user = self.membership.user
        except AttributeError:
            user = None
        return user

    @property
    def customer(self):
        """Returns the customer of the associated subscription"""
        return self.subscription.customer

    @property
    def role(self):
        """Returns the role of the associated membership or invitation"""
        if self.membership:
            return self.membership.role
        if self.invitation:
            return self.invitation.role
        return None


class TrialFeature(models.Model):
    STATE = Choices("pending", "visited", "started", "completed", "upgraded", "rejected")
    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE)
    name = models.SlugField()
    state = models.CharField(choices=STATE, default=STATE.pending, max_length=10)
    state_log = JSONMonitorField(monitor="state")

    class Meta:
        unique_together = ["subscription", "name"]

    def __str__(self) -> str:
        return f"{self.subscription.id} - {self.name} - {self.state}"

    @property
    def expiration_date(self):
        if self.name == "mdm":
            expiration_date = datetime.datetime(2021, 8, 20)
            return timezone.make_aware(expiration_date)
        raise ValueError()

    @property
    def has_expired(self):
        return timezone.now() > self.expiration_date

    @property
    def is_cleanup_date(self):
        return timezone.now() > self.expiration_date + datetime.timedelta(days=30)

    def _valid_transition(source: list[str], target: str):
        def wrap(func):
            def wrapper(self, *args, **kwargs):
                if self.state in source:
                    self.state = target
                    func(self, *args, **kwargs)
                else:
                    raise InvalidTransition()

            return wrapper

        return wrap

    def transition_to(self, state):
        try:
            transition_method = getattr(self, f"_transition_to_{state}")
            transition_method()
        except AttributeError:
            raise InvalidTransition()

    @_valid_transition(["pending", "visited"], "visited")
    def _transition_to_visited(self):
        pass

    @_valid_transition(["visited"], "started")
    def _transition_to_started(self):
        pass

    @_valid_transition(["started"], "completed")
    def _transition_to_completed(self):
        pass

    @_valid_transition(["pending", "visited", "completed"], "rejected")
    def _transition_to_rejected(self):
        pass

    @_valid_transition(["started", "completed"], "upgraded")
    def _transition_to_upgraded(self):
        pass


class UserScore(TimeStampedModel, SoftDeletableModel):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        verbose_name=_("user"),
        related_name="score",
        null=True,
        on_delete=models.SET_NULL,
    )
    email = models.EmailField(_("email address"), max_length=settings.TEXT_FIELD_STANDARD_LENGTH)
    total_score = models.SmallIntegerField(default=0)
    full_score_info = JSONField(default=dict, encoder=DjangoJSONEncoder, blank=True)
    score_calls_log = JSONField(default=list, encoder=DjangoJSONEncoder, blank=True)
    reassessed = models.BooleanField(default=False)

    objects = UserScoreManager()

    class Meta:
        verbose_name = _("user score")
        verbose_name_plural = _("users scores")
        ordering = ("user",)

    def __str__(self):
        return f"{self.email} - {self.total_score}"

    def update_score_call_log(self, vetting_request: dict, vetting_response: dict):
        """Update plan log."""
        self.score_calls_log.append({"vetting_request": vetting_request, "vetting_response": vetting_response})

    @property
    def has_organization_email(self):
        try:
            email_info = self.full_score_info["risk_hits"]["email"]
            return all(x not in email_info for x in {"Free", "Disposable"})
        except KeyError:
            return False

    @property
    def last_score_call(self):
        return self.score_calls_log[-1]

    def update_user_score(self, vetting_request: dict, vetting_response: dict, email=None):
        score = vetting_response["score"]["risk"]
        self.total_score = score
        self.full_score_info = vetting_response
        if email:
            self.email = email
        self.update_score_call_log(vetting_request, vetting_response)
        self.save()

    @property
    def phone_score(self):
        try:
            return self.full_score_info["area"]["phone"]
        except KeyError:
            return None

    @property
    def pass_limit_score(self):
        return self.reassessed or self.total_score >= settings.EHAWK_PASSING_LIMIT_SCORE

    @property
    def pass_block_score(self):
        return self.reassessed or self.total_score > settings.EHAWK_PASSING_BLOCK_SCORE

    @property
    def domain_always_bad(self):
        domain_info = self.full_score_info.get("risk_hits", {}).get("domain", [])
        email_domain_info = self.full_score_info.get("risk_hits", {}).get("email", [])
        return "Tagged Always Bad" in domain_info + email_domain_info


class CustomerCdnUsage(SoftDeletableModel):
    LIMIT_TYPES = Choices("mid", "total", "over")
    date = models.DateField()
    customer = models.ForeignKey(
        Customer,
        verbose_name="Customer CDN Usage",
        related_name="customer_cdn_usage",
        on_delete=models.CASCADE,
        unique_for_month="date",
    )
    limit_type = StatusField(choices_name="LIMIT_TYPES", null=True, blank=True, default=None)
    limit_type_log = JSONMonitorField(monitor="limit_type")
    usages_mb = models.DecimalField(default=0, max_digits=20, decimal_places=10)
    paid = models.BooleanField(default=False)

    class Meta:
        verbose_name = "customer cdn usage"
        verbose_name_plural = "customers cdn usage"

    def __str__(self):
        return f"{self.customer} - {self.date} - Current usages: {self.usages_mb}"

    def cdn_update(self, usages_limit, limit_type):
        self.limit_type = limit_type
        self.usages_mb = usages_limit
        self.save()


class CustomerConfigurationNeeded(models.Model):
    customer = models.ForeignKey(
        Customer,
        related_name="configuration_needed",
        on_delete=models.CASCADE,
    )
    label = models.SlugField()
    value = models.BooleanField(default=True)
    value_log = JSONMonitorField(monitor="value")

    class Meta:
        unique_together = ["customer", "label"]
        verbose_name = "customer configuration needed"
        verbose_name_plural = "customer configuration needed"

    def __str__(self):
        return f"{self.customer} - {self.label} - {self.value}"


class UserPhone(TimeStampedModel, models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    phone = models.CharField(max_length=30)
    phone_changes = models.SmallIntegerField(default=0)
    send_attempts = models.SmallIntegerField(default=0)
    confirmation_attempts = models.SmallIntegerField(default=0)

    class Meta:
        verbose_name = "User phone"
        verbose_name_plural = "Users phones"

    def __str__(self):
        return f"{self.user} - Phone: {self.phone}"

    @property
    def is_phone_score_valid(self):
        try:
            user_score = self.user.score
        except UserScore.DoesNotExist:
            return False

        phone_score = user_score.phone_score
        if phone_score is not None:
            return phone_score >= settings.AUTO_REASSESMENT_LIMITS["phone_score"]
        return False

    @property
    def change_phone_left_attempts(self):
        return settings.AUTO_REASSESMENT_LIMITS["phone_changes"] - self.phone_changes

    @property
    def send_code_left_attempts(self):
        return settings.AUTO_REASSESMENT_LIMITS["send_attempts"] - self.send_attempts

    @property
    def confirm_code_left_attempts(self):
        return settings.AUTO_REASSESMENT_LIMITS["confirmation_attempts"] - self.confirmation_attempts

    @property
    def is_phone_valid(self):
        return True  # FE needs an explicit field about phone validity

    def change_phone(self, phone):
        self.phone = phone
        self.phone_changes = self.phone_changes + 1
        self.send_attempts = 0
        self.confirmation_attempts = 0
        self.save()

    def add_send_attempt(self):
        self.send_attempts = self.send_attempts + 1
        self.confirmation_attempts = 0
        self.save()

    def add_confirmation_attempt(self):
        self.confirmation_attempts = self.confirmation_attempts + 1
        self.save()


class CustomerAiTokens(SoftDeletableModel):
    date = models.DateField()
    customer = models.ForeignKey(
        Customer,
        verbose_name="Customer AI Tokens",
        related_name="customer_ai_tokens",
        on_delete=models.CASCADE,
    )
    total_tokens = models.IntegerField()
    archived = models.BooleanField(default=False)

    objects = CustomerAiTokensManager()

    class Meta:
        verbose_name = "customer ai tokens"
        verbose_name_plural = "customers ai tokens"
        unique_together = ["customer", "date"]
        indexes = [
            models.Index(fields=["customer", "date", "archived"]),
        ]

    def __str__(self):
        return f"Customer: {self.customer.pk} - Date: {self.date} - Monthly total tokens: {self.total_tokens}"
