from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
import json
import logging
import user_agents
from django.conf import settings
from django.core.exceptions import ValidationError
from .token_utils import TokenService
from django.contrib.auth import authenticate
from .models import (
    AuditLog,
    Action,
    Device,
    UserDevice,
    DeviceSecurityPolicy,
    DevicePolicyAssignment,
)

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    MAX_DEVICES_PER_USER = 2  # will be changed

    def post(self, request, *args, **kwargs):
        """
        Handle user login with device tracking and return authentication tokens.
        """
        # Initialize variables at the beginning
        ip_address = self.get_client_ip(request)
        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        login_action, _ = Action.objects.get_or_create(
            name="login_attempt", defaults={"description": "User login attempt"}
        )

        try:
            # Parse device information
            device_info = self._parse_device_info(request)

            try:
                data = json.loads(request.body)
                email = data.get("email")
                password = data.get("password")
                device_uuid = data.get("device_uuid")  # Optional, for returning devices

                user = authenticate(request, email=email, password=password)
                if user and user.clearances.all():
                    user_department = user.clearances.all()[0].department
                    user_clearance = user.clearances.all()[0].clearance_level
                else:
                    # Handle users without clearances
                    user_department = None
                    user_clearance = None

            except json.JSONDecodeError:
                return self._handle_error(
                    None,
                    login_action,
                    "Invalid JSON format in request body",
                    AuditLog.ResultChoices.ERROR,
                    ip_address,
                    user_agent_string,
                    user_clearance,
                    user_department,
                )

            if not email or not password:
                return self._handle_error(
                    None,
                    login_action,
                    "Missing email or password",
                    AuditLog.ResultChoices.FAILURE,
                    ip_address,
                    user_agent_string,
                    user_clearance,
                    user_department,
                )

            if not user:
                return self._handle_error(
                    None,
                    login_action,
                    "Invalid credentials",
                    AuditLog.ResultChoices.FAILURE,
                    ip_address,
                    user_agent_string,
                    user_clearance,
                    user_department,
                )

            if not user.is_active:
                return self._handle_error(
                    user,
                    login_action,
                    "Account is not active",
                    AuditLog.ResultChoices.FAILURE,
                    ip_address,
                    user_agent_string,
                    user_clearance,
                    user_department,
                )

            try:
                # Handle device tracking
                device, user_device = self._handle_device_tracking(
                    user, device_info, device_uuid, ip_address
                )
            except DeviceLimitExceeded as e:
                # Get list of active devices for the user
                active_devices = UserDevice.objects.filter(
                    user=user, approval_status="approved"
                ).select_related("device")

                devices_info = [
                    {
                        "uuid": str(ud.device.uuid),
                        "device_name": ud.device.device_name or "Unknown Device",
                        "device_type": ud.device.device_type,
                        "last_seen_at": ud.device.last_seen_at.isoformat(),
                        "browser_type": ud.device.browser_type,
                        "os_type": ud.device.os_type,
                    }
                    for ud in active_devices
                ]

                # Create audit log for the failed attempt
                self._create_audit_log(
                    user=user,
                    action=login_action,
                    resource=None,
                    clearance_level=user_clearance,
                    department=user_department,
                    result=AuditLog.ResultChoices.FAILURE,
                    reason="Device limit exceeded",
                    ip_address=ip_address,
                    user_agent=user_agent_string,
                )

                return JsonResponse(
                    {
                        "error": str(e),
                        "code": "DEVICE_LIMIT_EXCEEDED",
                        "active_devices": devices_info,
                        "max_devices": self.MAX_DEVICES_PER_USER,
                    },
                    status=400,
                )

            # Generate tokens
            access_token = TokenService.generate_access_token(user)
            refresh_token = TokenService.generate_refresh_token(user)

            # Log successful login with device information
            self._create_audit_log(
                user=user,
                action=login_action,
                resource=None,
                clearance_level=user_clearance,
                department=user_department,
                result=AuditLog.ResultChoices.SUCCESS,
                reason="User logged in successfully",
                ip_address=ip_address,
                user_agent=user_agent_string,
                device=device,
            )

            return JsonResponse(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "username": user.username,
                    },
                    "device": {
                        "uuid": str(device.uuid),
                        "is_trusted": device.is_trusted,
                        "trust_expires_at": device.trust_expires_at.isoformat()
                        if device.trust_expires_at
                        else None,
                        "approval_status": user_device.approval_status,
                        "device_name": device.device_name,
                        "device_type": device.device_type,
                        "browser_type": device.browser_type,
                        "os_type": device.os_type,
                    },
                }
            )

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return JsonResponse(
                {
                    "error": "An error occurred during login",
                    "detail": str(e) if settings.DEBUG else None,
                },
                status=500,
            )

    def _parse_device_info(self, request):
        """
        Parse device information from the user agent string.
        """
        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        user_agent = user_agents.parse(user_agent_string)
        # print(user_agent_string)

        if "PostmanRuntime" in user_agent_string.lower():
            return {
                "device_type": "api_client",
                "device_name": "Postman Client",
                "os_type": "API Client",
                "os_version": "N/A",
                "browser_type": "Postman",
                "browser_version": "N/A",
            }

        return {
            "device_type": self._get_device_type(user_agent),
            "device_name": f"{user_agent.device.brand} {user_agent.device.model}",
            "os_type": user_agent.os.family,
            "os_version": user_agent.os.version_string,
            "browser_type": user_agent.browser.family,
            "browser_version": user_agent.browser.version_string,
        }

    def _get_device_type(self, user_agent):
        """
        Determine device type from user agent.
        """
        if user_agent.is_mobile:
            return "mobile"
        elif user_agent.is_tablet:
            return "tablet"
        elif user_agent.is_pc:
            return "desktop"
        return "other"

    def _handle_device_tracking(
        self, user, device_info, device_uuid=None, ip_address=None
    ):
        """
        Handle device tracking with improved device fingerprinting.
        """
        try:
            # Create a device fingerprint based on available info
            device_fingerprint = {
                "browser_type": device_info["browser_type"],
                "os_type": device_info["os_type"],
                "device_type": device_info["device_type"],
                "ip_address": ip_address,
            }

            # Try to find existing device by UUID first
            if device_uuid:
                try:
                    device = Device.objects.get(uuid=device_uuid)
                    user_device = UserDevice.objects.filter(
                        user=user, device=device
                    ).first()
                    if user_device:
                        self._update_device(device, device_info, ip_address)
                        return device, user_device
                except Device.DoesNotExist:
                    pass

            # Try to find an existing device with the same fingerprint for this user
            existing_device = Device.objects.filter(
                user_associations__user=user,
                browser_type=device_fingerprint["browser_type"],
                os_type=device_fingerprint["os_type"],
                device_type=device_fingerprint["device_type"],
                last_ip_address=device_fingerprint["ip_address"],
            ).first()

            if existing_device:
                user_device = UserDevice.objects.get(user=user, device=existing_device)
                self._update_device(existing_device, device_info, ip_address)
                compliance_status = self._check_device_compliance(existing_device, user)
                if not compliance_status["compliant"]:
                    raise ValidationError(
                        {
                            "error": "Device non-compliant",
                            "code": "DEVICE_NON_COMPLIANT",
                            "violations": compliance_status["violations"],
                            "required_actions": compliance_status["required_actions"],
                        }
                    )

                return existing_device, user_device

            # Count user's active devices if we need to create a new one
            active_devices_count = UserDevice.objects.filter(
                user=user, approval_status="approved"
            ).count()

            # If this is a new device and user has reached the limit
            if active_devices_count >= self.MAX_DEVICES_PER_USER:
                raise DeviceLimitExceeded(
                    "Maximum device limit reached. Please log out from another device first.",
                    active_devices=UserDevice.objects.filter(
                        user=user, approval_status="approved"
                    ).select_related("device"),
                )

            # Create new device
            device = Device.objects.create(**device_info, last_ip_address=ip_address)
            compliance_status = self._check_device_compliance(device, user)
            if not compliance_status["compliant"]:
                device.delete()  # Clean up non-compliant device
                raise ValidationError(
                    {
                        "error": "Device non-compliant",
                        "code": "DEVICE_NON_COMPLIANT",
                        "violations": compliance_status["violations"],
                        "required_actions": compliance_status["required_actions"],
                    }
                )

            # Create UserDevice association
            user_device = UserDevice.objects.create(
                user=user,
                device=device,
                approval_status="approved",
                is_primary=not UserDevice.objects.filter(user=user).exists(),
            )

            # Apply default security policy if available
            self._apply_default_security_policy(device)

            return device, user_device

        except DeviceLimitExceeded:
            raise
        except Exception as e:
            logger.error(f"Error in device tracking: {str(e)}")
            raise

    def _update_device(self, device, device_info, ip_address):
        """
        Update device information
        """
        for key, value in device_info.items():
            setattr(device, key, value)
        device.last_ip_address = ip_address
        device.last_seen_at = timezone.now()
        device.save()

    def _apply_default_security_policy(self, device):
        """
        Apply default security policy to device if available.
        """
        try:
            default_policy = DeviceSecurityPolicy.objects.filter(name="default").first()

            if default_policy:
                DevicePolicyAssignment.objects.get_or_create(
                    device=device, policy=default_policy
                )
        except Exception as e:
            logger.error(f"Error applying default security policy: {str(e)}")

    def _handle_error(
        self,
        user,
        action,
        reason,
        result,
        ip_address,
        user_agent,
        clearance_level,
        department,
    ):
        """
        Handle error responses with audit logging.
        """
        self._create_audit_log(
            user=user,
            action=action,
            resource=None,
            clearance_level=clearance_level,
            department=department,
            result=result,
            reason=reason,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return JsonResponse({"error": reason}, status=401)

    def _create_audit_log(self, **kwargs):
        """
        Helper method to create audit log entries using the model's log method.
        """
        try:
            AuditLog.log(**kwargs)
        except Exception as e:
            logger.error(f"Error creating audit log: {str(e)}")

    def get_client_ip(self, request):
        """
        Get client IP address from request
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")

    def _check_device_compliance(self, device, user):
        """
        Check if device complies with applicable security policies.
        """
        compliance_status = {
            "compliant": True,
            "violations": [],
            "required_actions": [],
        }

        try:
            # Get applicable policies (user department policy or default policy)
            policies = self._get_applicable_policies(user)

            if not policies:
                return compliance_status  # No policies to check against

            for policy in policies:
                # Check OS version requirements
                if policy.required_os_versions:
                    required_version = policy.required_os_versions.get(device.os_type)
                    if required_version:
                        device_version = self._parse_version(device.os_version)
                        required = self._parse_version(required_version)

                        if device_version < required:
                            compliance_status["compliant"] = False
                            compliance_status["violations"].append(
                                f"OS version {device.os_version} below required {required_version}"
                            )
                            compliance_status["required_actions"].append(
                                f"Update {device.os_type} to version {required_version} or higher"
                            )

                # Check security features
                if policy.required_security_features:
                    # In a real implementation, you would get these from the device
                    # For now, we'll assume the device info includes security_features
                    device_features = getattr(
                        device, "security_features", []
                    )  # not included for now
                    missing_features = set(policy.required_security_features) - set(
                        device_features
                    )

                    if missing_features:
                        compliance_status["compliant"] = False
                        compliance_status["violations"].append(
                            f"Missing security features: {', '.join(missing_features)}"
                        )
                        compliance_status["required_actions"].append(
                            f"Enable the following security features: {', '.join(missing_features)}"
                        )

                # Check device activity
                if policy.max_inactive_days:
                    if device.last_seen_at:
                        inactive_days = (timezone.now() - device.last_seen_at).days
                        if inactive_days > policy.max_inactive_days:
                            compliance_status["compliant"] = False
                            compliance_status["violations"].append(
                                f"Device inactive for {inactive_days} days (max {policy.max_inactive_days})"
                            )
                            compliance_status["required_actions"].append(
                                "Re-validate device through security check"
                            )

        except Exception as e:
            logger.error(f"Error checking device compliance: {str(e)}")
            compliance_status["compliant"] = False
            compliance_status["violations"].append("Error checking compliance")

        return compliance_status

    def _get_applicable_policies(self, user):
        """
        Get security policies applicable to the user.
        """
        policies = []

        # Get user's department policy if available
        if hasattr(user, "clearances") and user.clearances.exists():
            department = user.clearances.first().department
            dept_policies = DeviceSecurityPolicy.objects.filter(departments=department)
            policies.extend(dept_policies)

        # Get default policy if no department policy exists
        if not policies:
            default_policy = DeviceSecurityPolicy.objects.filter(name="default").first()
            if default_policy:
                policies.append(default_policy)

        return policies

    def _parse_version(self, version_string):
        """
        Parse version string into comparable tuple.
        """
        try:
            return tuple(map(int, (version_string.split("."))))
        except (AttributeError, ValueError):
            return (0,)  # Return minimal version if parsing fails

    def _apply_security_policy(self, device, user):
        """
        Apply appropriate security policy to device.
        """
        policies = self._get_applicable_policies(user)
        for policy in policies:
            DevicePolicyAssignment.objects.get_or_create(
                device=device, policy=policy, defaults={"assigned_at": timezone.now()}
            )


class DeviceLimitExceeded(Exception):
    def __init__(self, message, active_devices):
        super().__init__(message)
        self.active_devices = active_devices


@method_decorator(csrf_exempt, name="dispatch")
class DeviceLogoutView(View):
    def post(self, request, device_uuid):
        try:
            # Get the device
            device = Device.objects.get(uuid=device_uuid)

            # Remove the UserDevice association
            UserDevice.objects.filter(device=device, approval_status="approved").update(
                approval_status="logged_out"
            )

            return JsonResponse({"message": "Device logged out successfully"})

        except Device.DoesNotExist:
            return JsonResponse({"error": "Device not found"}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
