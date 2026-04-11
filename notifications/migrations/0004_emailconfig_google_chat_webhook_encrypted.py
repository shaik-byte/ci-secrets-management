from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("notifications", "0003_encrypt_email_app_password"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailconfig",
            name="google_chat_webhook_encrypted",
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
