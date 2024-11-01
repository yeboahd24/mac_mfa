# Generated by Django 5.1.2 on 2024-10-25 23:07

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(db_index=True, error_messages={'unique': 'A user with that email already exists.'}, max_length=254, unique=True, verbose_name='email address')),
                ('username', models.CharField(db_index=True, error_messages={'unique': 'A user with that username already exists.'}, max_length=255, unique=True, verbose_name='username')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Action',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(db_index=True, max_length=255, unique=True, verbose_name='name')),
                ('description', models.TextField(blank=True, verbose_name='description')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'action',
                'verbose_name_plural': 'actions',
                'ordering': ['name'],
                'indexes': [models.Index(fields=['name'], name='user_action_name_dc9d65_idx')],
            },
        ),
        migrations.CreateModel(
            name='Department',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(db_index=True, max_length=255, unique=True, verbose_name='name')),
                ('description', models.TextField(blank=True, verbose_name='description')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='subdepartments', to='user.department')),
            ],
            options={
                'verbose_name': 'department',
                'verbose_name_plural': 'departments',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Patient',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=255, verbose_name='first name')),
                ('last_name', models.CharField(max_length=255, verbose_name='last name')),
                ('date_of_birth', models.DateField(verbose_name='date of birth')),
                ('gender', models.CharField(choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other'), ('N', 'Prefer not to say')], default='N', max_length=1)),
                ('classification', models.IntegerField(help_text='Patient data classification level', validators=[django.core.validators.MinValueValidator(0)], verbose_name='classification')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='patients_created', to=settings.AUTH_USER_MODEL)),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='patients', to='user.department')),
                ('last_updated_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='patients_updated', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'patient',
                'verbose_name_plural': 'patients',
                'ordering': ['last_name', 'first_name'],
                'permissions': [('view_sensitive_data', 'Can view sensitive patient data'), ('export_patient_data', 'Can export patient data')],
            },
        ),
        migrations.CreateModel(
            name='MedicalRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('diagnosis', models.TextField(verbose_name='diagnosis')),
                ('prescription', models.TextField(verbose_name='prescription')),
                ('notes', models.TextField(blank=True, verbose_name='notes')),
                ('attachments', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='medical_records_created', to=settings.AUTH_USER_MODEL)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='medical_records_doctor', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='medical_records_updated', to=settings.AUTH_USER_MODEL)),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='user.patient')),
            ],
            options={
                'verbose_name': 'medical record',
                'verbose_name_plural': 'medical records',
                'ordering': ['-created_at'],
                'permissions': [('modify_diagnosis', 'Can modify diagnosis'), ('delete_record', 'Can delete medical record')],
            },
        ),
        migrations.CreateModel(
            name='Prescription',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('medication', models.CharField(max_length=255, verbose_name='medication')),
                ('dosage', models.CharField(max_length=255, verbose_name='dosage')),
                ('instructions', models.TextField(verbose_name='instructions')),
                ('start_date', models.DateField(default=django.utils.timezone.now, verbose_name='start date')),
                ('end_date', models.DateField(blank=True, null=True, verbose_name='end date')),
                ('refills_remaining', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='prescriptions_created', to=settings.AUTH_USER_MODEL)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='prescriptions_doctor', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='prescriptions_updated', to=settings.AUTH_USER_MODEL)),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='user.patient')),
            ],
            options={
                'verbose_name': 'prescription',
                'verbose_name_plural': 'prescriptions',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Resource',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(db_index=True, max_length=255, verbose_name='name')),
                ('description', models.TextField(blank=True, verbose_name='description')),
                ('classification_level', models.IntegerField(db_index=True, verbose_name='classification level')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.department')),
            ],
            options={
                'verbose_name': 'resource',
                'verbose_name_plural': 'resources',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(db_index=True, max_length=255, unique=True, verbose_name='name')),
                ('description', models.TextField(blank=True, verbose_name='description')),
                ('hierarchy_level', models.IntegerField(verbose_name='hierarchy level')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'role',
                'verbose_name_plural': 'roles',
                'ordering': ['hierarchy_level', 'name'],
                'indexes': [models.Index(fields=['hierarchy_level'], name='user_role_hierarc_434d10_idx')],
            },
        ),
        migrations.CreateModel(
            name='RolePermission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('required_clearance_level', models.IntegerField(validators=[django.core.validators.MinValueValidator(0)], verbose_name='required clearance level')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('action', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.action')),
                ('resource', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.resource')),
                ('role', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='permissions', to='user.role')),
            ],
            options={
                'verbose_name': 'role permission',
                'verbose_name_plural': 'role permissions',
            },
        ),
        migrations.CreateModel(
            name='SecurityClearanceLevel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(db_index=True, max_length=255, unique=True, verbose_name='name')),
                ('level', models.IntegerField(db_index=True, unique=True, verbose_name='level')),
                ('description', models.TextField(blank=True, verbose_name='description')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'security clearance level',
                'verbose_name_plural': 'security clearance levels',
                'ordering': ['level'],
                'indexes': [models.Index(fields=['level'], name='user_securi_level_8e8f46_idx')],
            },
        ),
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('result', models.CharField(choices=[('success', 'Success'), ('failure', 'Failure'), ('error', 'Error')], default='success', max_length=10)),
                ('reason', models.TextField()),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('action', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='user.action')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='user.department')),
                ('resource', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='user.resource')),
                ('clearance_level', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='user.securityclearancelevel')),
            ],
            options={
                'verbose_name': 'audit log',
                'verbose_name_plural': 'audit logs',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='UserClearance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('granted_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('expires_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('clearance_level', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.securityclearancelevel')),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.department')),
                ('granted_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='clearances_granted', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='clearances', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user clearance',
                'verbose_name_plural': 'user clearances',
                'ordering': ['-granted_at'],
            },
        ),
        migrations.CreateModel(
            name='UserRole',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('role', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.role')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user role',
                'verbose_name_plural': 'user roles',
            },
        ),
        migrations.AddField(
            model_name='user',
            name='roles',
            field=models.ManyToManyField(through='user.UserRole', to='user.role'),
        ),
        migrations.AddIndex(
            model_name='department',
            index=models.Index(fields=['name'], name='user_depart_name_2ae1e3_idx'),
        ),
        migrations.AddIndex(
            model_name='patient',
            index=models.Index(fields=['last_name', 'first_name'], name='user_patien_last_na_5cabd5_idx'),
        ),
        migrations.AddIndex(
            model_name='patient',
            index=models.Index(fields=['date_of_birth'], name='user_patien_date_of_36a297_idx'),
        ),
        migrations.AddIndex(
            model_name='patient',
            index=models.Index(fields=['classification'], name='user_patien_classif_9e661e_idx'),
        ),
        migrations.AddIndex(
            model_name='medicalrecord',
            index=models.Index(fields=['patient', 'doctor'], name='user_medica_patient_ff396a_idx'),
        ),
        migrations.AddIndex(
            model_name='medicalrecord',
            index=models.Index(fields=['created_at'], name='user_medica_created_286940_idx'),
        ),
        migrations.AddIndex(
            model_name='prescription',
            index=models.Index(fields=['patient', 'doctor'], name='user_prescr_patient_774fd4_idx'),
        ),
        migrations.AddIndex(
            model_name='prescription',
            index=models.Index(fields=['medication'], name='user_prescr_medicat_470068_idx'),
        ),
        migrations.AddIndex(
            model_name='prescription',
            index=models.Index(fields=['start_date', 'end_date'], name='user_prescr_start_d_5a98da_idx'),
        ),
        migrations.AddIndex(
            model_name='resource',
            index=models.Index(fields=['classification_level', 'department'], name='user_resour_classif_c8e3be_idx'),
        ),
        migrations.AddIndex(
            model_name='rolepermission',
            index=models.Index(fields=['role', 'resource', 'action'], name='user_rolepe_role_id_cb6294_idx'),
        ),
        migrations.AddIndex(
            model_name='rolepermission',
            index=models.Index(fields=['required_clearance_level'], name='user_rolepe_require_d79bae_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='rolepermission',
            unique_together={('role', 'resource', 'action')},
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['user', 'action', 'resource'], name='user_auditl_user_id_efb097_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['created_at'], name='user_auditl_created_44aa49_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['result'], name='user_auditl_result_72f167_idx'),
        ),
        migrations.AddIndex(
            model_name='userclearance',
            index=models.Index(fields=['user', 'clearance_level', 'department'], name='user_usercl_user_id_debc2f_idx'),
        ),
        migrations.AddIndex(
            model_name='userclearance',
            index=models.Index(fields=['expires_at'], name='user_usercl_expires_961986_idx'),
        ),
        migrations.AddIndex(
            model_name='userrole',
            index=models.Index(fields=['user', 'role'], name='user_userro_user_id_d26808_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='userrole',
            unique_together={('user', 'role')},
        ),
        migrations.AddIndex(
            model_name='user',
            index=models.Index(fields=['email', 'username'], name='user_user_email_514b8f_idx'),
        ),
    ]
