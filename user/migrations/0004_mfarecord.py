# Generated by Django 5.1.2 on 2024-10-28 16:08

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_devicepolicyassignment_devicesecuritypolicy_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='MFARecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('secret_key', models.CharField(max_length=255, unique=True)),
                ('totp_code', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mfa_records', to='user.userdevice')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'MFA record',
                'verbose_name_plural': 'MFA records',
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['user', 'device'], name='user_mfarec_user_id_13a552_idx'), models.Index(fields=['created_at'], name='user_mfarec_created_647e65_idx')],
            },
        ),
    ]