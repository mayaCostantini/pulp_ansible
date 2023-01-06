# Generated by Django 3.2.16 on 2023-01-04 15:44

from django.db import migrations, models
import django.db.models.deletion
import django_lifecycle.mixins
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0098_pulp_labels'),
        ('ansible', '0046_add_fulltext_search_fix'),
    ]

    operations = [
        migrations.CreateModel(
            name='OIDCIdentity',
            fields=[
                ('pulp_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('pulp_created', models.DateTimeField(auto_now_add=True)),
                ('pulp_last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('identity', models.TextField(db_index=True, unique=True)),
            ],
            options={
                'abstract': False,
            },
            bases=(django_lifecycle.mixins.LifecycleModelMixin, models.Model),
        ),
        migrations.CreateModel(
            name='SigstoreVerifyingService',
            fields=[
                ('pulp_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('pulp_created', models.DateTimeField(auto_now_add=True)),
                ('pulp_last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('sigstore_rekor_instance', models.TextField(default='https://rekor.sigstore.dev')),
                ('sigstore_verification_policies', models.TextField(default=None)),
            ],
            options={
                'abstract': False,
            },
            bases=(django_lifecycle.mixins.LifecycleModelMixin, models.Model),
        ),
        migrations.CreateModel(
            name='SigstoreSigningService',
            fields=[
                ('pulp_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('pulp_created', models.DateTimeField(auto_now_add=True)),
                ('pulp_last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('sigstore_rekor_instance', models.TextField(default='https://rekor.sigstore.dev')),
                ('sigstore_fulcio_instance', models.TextField(default='https://fulcio.sigstore.dev')),
                ('sigstore_oidc_identity', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sigstore_signing_service', to='ansible.oidcidentity')),
            ],
            options={
                'abstract': False,
            },
            bases=(django_lifecycle.mixins.LifecycleModelMixin, models.Model),
        ),
        migrations.CreateModel(
            name='SigstoreOIDCCredentials',
            fields=[
                ('pulp_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('pulp_created', models.DateTimeField(auto_now_add=True)),
                ('pulp_last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('sigstore_oidc_identity', models.TextField()),
                ('sigstore_oidc_client_id', models.CharField(max_length=64)),
                ('sigstore_oidc_client_secret', models.CharField(max_length=64)),
            ],
            options={
                'default_related_name': '%(app_label)s_%(model_name)s',
                'unique_together': {('sigstore_oidc_client_id', 'sigstore_oidc_client_secret')},
            },
            bases=(django_lifecycle.mixins.LifecycleModelMixin, models.Model),
        ),
        migrations.AddField(
            model_name='oidcidentity',
            name='sigstore_oidc_credentials',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='oidc_identities', to='ansible.sigstoreoidccredentials'),
        ),
        migrations.AddField(
            model_name='ansiblerepository',
            name='sigstore_verifying_service',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ansible_repositories', to='ansible.sigstoreverifyingservice'),
        ),
        migrations.CreateModel(
            name='CollectionVersionSigstoreSignature',
            fields=[
                ('content_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, related_name='ansible_collectionversionsigstoresignature', serialize=False, to='core.content')),
                ('data', models.BinaryField()),
                ('digest', models.CharField(max_length=64)),
                ('sigstore_x509_certificate', models.BinaryField()),
                ('sigstore_x509_certificate_sha256_digest', models.CharField(max_length=64)),
                ('signed_collection', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sigstore_signatures', to='ansible.collectionversion')),
                ('sigstore_signing_service', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sigstore_signatures', to='ansible.sigstoresigningservice')),
            ],
            options={
                'default_related_name': '%(app_label)s_%(model_name)s',
                'unique_together': {('sigstore_x509_certificate_sha256_digest', 'signed_collection')},
            },
            bases=('core.content',),
        ),
    ]
