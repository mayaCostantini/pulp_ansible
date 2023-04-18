# Generated by Django 3.2.18 on 2023-04-18 13:49

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0102_add_domain_relations'),
        ('ansible', '0051_cvindex_build'),
    ]

    operations = [
        migrations.CreateModel(
            name='SigstoreSigningService',
            fields=[
                ('content_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, related_name='ansible_sigstoresigningservice', serialize=False, to='core.content')),
                ('name', models.CharField(db_index=True, max_length=64, unique=True)),
                ('rekor_url', models.TextField(default='https://rekor.sigstore.dev')),
                ('rekor_root_pubkey', models.TextField(null=True)),
                ('fulcio_url', models.TextField(default='https://fulcio.sigstore.dev')),
                ('tuf_url', models.TextField(default='https://sigstore-tuf-root.storage.googleapis.com/')),
                ('oidc_issuer', models.TextField(default='https://oauth2.sigstore.dev/auth')),
                ('credentials_file_path', models.TextField(null=True)),
                ('ctfe_pubkey', models.TextField(null=True)),
                ('enable_interactive', models.BooleanField(default=False)),
            ],
            options={
                'default_related_name': '%(app_label)s_%(model_name)s',
            },
            bases=('core.content',),
        ),
        migrations.CreateModel(
            name='SigstoreVerifyingService',
            fields=[
                ('content_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, related_name='ansible_sigstoreverifyingservice', serialize=False, to='core.content')),
                ('name', models.CharField(db_index=True, max_length=64, unique=True)),
                ('rekor_url', models.TextField(default='https://rekor.sigstore.dev')),
                ('rekor_root_pubkey', models.TextField(null=True)),
                ('certificate_chain', models.TextField(null=True)),
                ('expected_oidc_issuer', models.TextField()),
                ('expected_identity', models.TextField()),
                ('verify_offline', models.BooleanField(default=False, null=True)),
            ],
            options={
                'default_related_name': '%(app_label)s_%(model_name)s',
            },
            bases=('core.content',),
        ),
        migrations.AddField(
            model_name='ansiblerepository',
            name='sigstore_signing_service',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ansible_repositories', to='ansible.sigstoresigningservice'),
        ),
        migrations.AddField(
            model_name='ansiblerepository',
            name='sigstore_verifying_service',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ansible_repositories', to='ansible.sigstoreverifyingservice'),
        ),
        migrations.CreateModel(
            name='CollectionVersionSigstoreSignature',
            fields=[
                ('content_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, related_name='ansible_collectionversionsigstoresignature', serialize=False, to='core.content')),
                ('data', models.CharField(max_length=256)),
                ('sigstore_x509_certificate', models.TextField()),
                ('sigstore_bundle', models.JSONField(null=True)),
                ('signed_collection', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sigstore_signatures', to='ansible.collectionversion')),
                ('sigstore_signing_service', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sigstore_signatures', to='ansible.sigstoresigningservice')),
            ],
            options={
                'default_related_name': '%(app_label)s_%(model_name)s',
                'unique_together': {('sigstore_x509_certificate', 'signed_collection')},
            },
            bases=('core.content',),
        ),
    ]
