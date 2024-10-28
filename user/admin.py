from django.contrib import admin
from .models import (
    User,
    Action,
    Resource,
    Role,
    RolePermission,
    SecurityClearanceLevel,
    AuditLog,
    UserClearance,
    UserRole,
    Patient,
    MedicalRecord,
    Prescription,
    Department,
    Device,
    UserDevice,
    DeviceSecurityPolicy,
    DevicePolicyAssignment,
)


admin.site.register(User)
admin.site.register(Action)
admin.site.register(Resource)
admin.site.register(Role)
admin.site.register(RolePermission)
admin.site.register(SecurityClearanceLevel)
admin.site.register(AuditLog)
admin.site.register(UserClearance)
admin.site.register(UserRole)
admin.site.register(Patient)
admin.site.register(MedicalRecord)
admin.site.register(Prescription)
admin.site.register(Department)
admin.site.register(Device)
admin.site.register(UserDevice)
admin.site.register(DeviceSecurityPolicy)
admin.site.register(DevicePolicyAssignment)
