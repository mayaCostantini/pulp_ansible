===================
Signature Workflows
===================

``pulp_ansible`` supports Collection signing, syncing, and uploading. Collection signing adds extra
validation when installing Collections with `ansible-galaxy`. Check out the workflows below to see
how to add signature support.
Two types of signing workflow are supported in ``pulp_ansible``: signing using a self-managed private key (GPG flow) and using `Sigstore <https://sigstore.dev/>`__.

Signing Ansible collections with GPG
====================================

Setup
-----
In order to verify signature validity on uploads you will need to store your trusted key on the
repositories ``gpgkey`` attribute.

.. note::
   You can upload signatures without supplying Pulp any key, but ``pulp_ansible`` will not
   perform validity checks on the uploaded signature. You will also have to configure the
   ``ANSIBLE_SIGNATURE_REQUIRE_VERIFICATION`` setting to ``False``. By default and once a key is
   provided, all signatures impossible to verify are rejected.

In order to have ``pulp_ansible`` sign collections stored in your repositories you will need to set
up a signing service. First, create/import the key you intend to sign your collections with onto
your Pulp system. Second, create a signing script on your Pulp system with the parameters you want
on the generated signatures. Galaxy uses a signing script like the one below:

.. code-block:: bash

    #!/usr/bin/env bash
    FILE_PATH=$1
    SIGNATURE_PATH="$1.asc"

    # Create a detached signature
    gpg --quiet --batch --homedir ~/.gnupg/ --detach-sign --local-user "${PULP_SIGNING_KEY_FINGERPRINT}" \
        --armor --output ${SIGNATURE_PATH} ${FILE_PATH}

    # Check the exit status
    STATUS=$?
    if [[ ${STATUS} -eq 0 ]]; then
       echo {\"file\": \"${FILE_PATH}\", \"signature\": \"${SIGNATURE_PATH}\"}
    else
       exit ${STATUS}
    fi

Third, create the signing service using ``pulpcore-manager``:

.. code-block:: bash

    pulpcore-manager add-signing-service ansible-signing-service $SCRIPT_LOCATION $PUBKEY_FINGERPRINT

Reference: `Signing Service <https://docs.pulpproject.org/pulpcore/workflows/signed-metadata.html>`_

Signing Collections
-------------------

Sign collections stored in repository ``foo`` with the signing service ``ansible-signing-service``:

.. code-block:: bash

    pulp ansible repository sign --name foo --signing-service ansible-signing-service

By default it will sign everything in the repository, specify ``--content-units`` with a list of
specific collection hrefs you want to sign. Collections can have multiple signatures attached to
them in a repository as long as they are all from different keys.

Syncing Signed Collections
--------------------------

Signature information will be present in the Galaxy APIs if your repository has signatures in it
and when syncing from a Galaxy repository, signatures will automatically be synced as well if
present. You can also specify to only sync Collections that have signatures with the
``signed_only`` field on the remote. e.g.:

.. code-block:: bash

    pulp ansible remote update --name foo --signed-only
    # Sync task will only sync collections with signatures now
    pulp ansible repository sync --name foo --remote foo

Uploading Signed Collections
----------------------------

Signatures can also be manually created and uploaded to ``pulp_ansible``.

.. code-block:: bash

    pulp ansible content -t signature upload --file $SIGNATURE --collection $COLLECTION_HREF

Signatures can be verified upon upload by setting the ``keyring`` field on the repository to your
keyring location, and then specifying the ``repository`` option when uploading the signature.

.. code-block:: bash

    pulp ansible repository update --name foo --keyring $KEYRING_FILE_LOCATION
    # Validate signature against keyring of repository
    pulp ansible content -t signature upload --file $SIGNATURE --collection $COLLECTION_HREF --repository foo

Verifying Signatures with ``ansible-galaxy``
--------------------------------------------

Installing collections from ``pulp_ansible`` with signatures via `ansible-galaxy` requires
specifying the keyring to perform the validation upon install:

.. code-block:: bash

    ansible-galaxy collection install $COLLECTION -s "$BASE_ADDR"pulp_ansible/galaxy/foo/api/ --keyring $KEYRING_FILE_LOCATION

You can also verify already installed collections with the verify command:

.. code-block:: bash

    ansible-galaxy collection verify $COLLECTION -s "$BASE_ADDR"pulp_ansible/galaxy/foo/api/ --keyring $KEYRING_FILE_LOCATION


Signing content with Sigstore
=============================


What is Sigstore?
-----------------

Sigstore is a new standard for signing, verifying and protecting software.
It allows developers to sign artifacts using a self-managed key pair or using a "keyless" signing flow and to store signing materials in a tamper-resistant transparency log.

How does Sigstore work?
-----------------------

Sigstore can sign artifacts by authentifying signers via an `OpenID Connect flow <https://openid.net/connect/>`__
, redirecting them to an identity provider such as Google, Microsoft or GitHub.
When a proof of identity is obtained from one of those providers, it is used to generate an ephemeral signing certificate with Sigstore's Certificate Authority `Fulcio <https://docs.sigstore.dev/fulcio/overview/>`_.
The Sigstore client then uses this certificate and an ephemeral key pair to sign the artifact,
and stores the signing materials in the `Rekor <https://docs.sigstore.dev/rekor/overview/>`_
transparency log for everyone to verify the integrity and authenticity of the artifact signature.

It is also possible to sign artifacts with Sigstore using a self-managed key pair as for GPG.

Sigstore signing for Ansible collections in ``pulp_ansible`` supports using both public and private instances of Rekor, Fulcio and of an OIDC provider.
Using private instances is recommended for signing private collections that will not be published outside an organization,
as sensitive information such as corporate emails used as signing identities are published by Rekor and Fulcio and thus visible by everyone on the public instances. 

General documentation about Sigstore can be found on `docs.sigstore.dev <https://docs.sigstore.dev/>`_.

Getting started with signing collections with Sigstore
------------------------------------------------------

------------------------------------------------
Sigstore installation and configuration overview
------------------------------------------------

The Sigstore community maintains public good instances of `Rekor <https://rekor.sigstore.dev>`__
and `Fulcio <https://fulcio.sigstore.dev>`__
available for everyone to sign and verify content against.

It is advised to use those instances to sign your Ansible collections if those are public-facing and when no sensitive information
(for example, a corporate email) is used to sign the content.

If the content you are signing is supposed to stay internal-only, you should have your own deployment of Sigstore as 
**information present in the public Transparency Log is available to anyone and cannot be altered or removed once logged**.

To learn how to deploy a private Sigstore instance on a single Virtual Machine with Keycloak as an OIDC provider, follow the `documentation <https://github.com/sabre1041/sigstore-ansible>`__.

--------------------------------------
Configuring a Sigstore Signing Service
--------------------------------------

``pulp_ansible`` allows Pulp administrators to configure Sigstore Signing Service objects to manage the way content is signed and verified in Ansible repositories.
Sigstore Signing Services specify the following options:

- **name [Required]**: the name of the Sigstore Signing Service
- **environment [Optional]**: If Pulp is installed in a cloud environment, this option allows to automatically identify through the provider identity flow when using keyless signing.
- **rekor_url [Optional]**: The URL of the Rekor instance to use to log signatures. Defaults to the public instance `<https://rekor.sigstore.dev>`__.
- **fulcio_url [Optional]**: The URL of the Fulcio instance to use to get signing certificates. Defaults to the public instance `<https://fulcio.sigstore.dev>`__.
- **tuf_url [Optional]**: The URL of the TUF metadata repository to use. Defaults to the public instance `<https://sigstore-tuf-root.storage.googleapis.com/>`__.
- **rekor_root_pubkey [Optional]**: PEM-encoded public key file for Rekor. Defaults to the public key of the public Rekor instance.
- **oidc_issuer [Optional]**: The URL of the OIDC issuer instance to use to identify to Sigstore. Defaults to the public Sigstore OAuth2 server `<https://oauth2.sigstore.dev/auth>`__.
- **expected_oidc_provider [Required]**: The identity issuer that should figure in the signing certificate for verification.
- **credentials_file_path [Optional]**: The path on the Pulp server to a JSON file containing the OIDC client ID and client secret for authentication. Defaults to ``/var/lib/pulp/media/credentials.json``.
- **ctfe [Optional]**: PEM-encoded public key file for Fulcio's Certificate Transparency Log (CTLog). Defaults to the public key of the public CTLog instance.
- **cert_identity [Required]**: Expected identity (email) to be found when verifying the signing certificate.
- **verify_offline [Optional]**: Offline signature verification using a Sigstore bundle. Defaults to ``false``.
- **sigstore_bundle [Optional]**: Output a Sigstore bundle object when signing a collection. Required for offline verification. Defaults to ``true``.
- **set_keycloak [Optional]**: Set Keycloak as the OIDC provider. Defaults to ``true``.
- **disable_interactive [Optional]**: Disable Sigstore's interactive browser flow for signing collections. Defaults to ``true``.

A Sigstore Signing Service can be added to ``pulp_ansible`` in two manners:

**Using the pulpcore-manager command line**

The configuration for a Sigstore Signing Service can be loaded from a JSON file containing the above fields.
Here is an example of valid Sigstore Signing Configuration:

.. code-block:: json
    :caption: sigstore-signing-service-config.json

    {
        "global-options": {
            "name": "my-sigstore-signing-service",
            "environment": "amazon_web_services",
            "rekor-url": "https://rekor.sigstore.dev",
            "oidc-issuer": "https://oauth2.sigstore.dev/auth",
            "tuf-url": "https://sigstore-tuf-root.storage.googleapis.com/",
        },
        "sign-options": {
            "fulcio-url": "https://fulcio.sigstore.dev",
            "ctfe": null,
            "sigstore-bundle": true,
            "credentials-file-path": "/var/lib/pulp/media/my-credentials.json",
            "set-keycloak": true,
            "disable-interactive": true
        },
        "verify-options": {
            "expected-oidc-provider": "https://github.com/login/oauth",
            "cert-idenity": "youremail@example.com",
            "verify-offline": true
        }
    }

To create a Sigstore Signing Service from a file, run the following command:

.. code-block:: bash

    pulpcore-manager add-sigstore-signing-service sigstore-signing-service-config.json

Any of the fields can be overriden by using command line options. For example:

.. code-block:: bash

    pulpcore-manager add-sigstore-signing-service sigstore-signing-service-config.json --name=another-name --set-keycloak=false --oidc-issuer=http://localhost:8080/realms/sigstore/

**Using the Pulp API UI**

To add a Sigstore Signing Service with the API, it is necessary to be logged in as an administrator.
The endpoint to add a Sigstore Signing Service to ``pulp_ansible`` can be found at ``/pulp/api/v3/content/ansible/sigstore_signing_services/``.

..
    TODO: add note about cert identity and Keycloak service accounts.

--------------------------------------------
Signing Collections in an Ansible Repository
--------------------------------------------

To sign collections stored in repository ``foo`` with the Sigstore Signing Service:

.. code-block:: bash

    pulp ansible repository sign --name foo --sigstore-signing-service ansible-signing-service

If the interactive flow is enabled, a browser window will open for the signer to authentify with Sigstore.
**Note**: the identity provider to choose when signing should be the one specified as the ``expected_identity_provider`` and the sign-in email the same as the ``cert-identity``.
This will allow the same Sigstore Signing Service to verify successfully the signatures by looking for those fields in the signing certificate Subject Alternative Name (SAN).

If the interactive signing flow is disabled, the credentials in the file located at ``credentials_file_path`` will be used to get a proof of identity from the specified ``oidc_issuer``.

------------------------------------------
Uploading Collections Signed with Sigstore
------------------------------------------

Signatures can also be manually created using the `ansible-sign <https://github.com/ansible/ansible-sign>`__ 
command line interface and uploaded to ``pulp_ansible``.

.. code-block:: bash

    pulp ansible content -t sigtsore-signature upload --signature $SIGSTORE_SIGNATURE --certificate $SIGSTORE_CERTIFICATE --bundle $SIGSTORE_BUNDLE --collection $COLLECTION_HREF


Sigstore Signatures can be verified upon upload by setting the ``sigstore_signing_service`` field on the repository to the Sigstore Signing Service to use for verification,
and then specifying the repository option when uploading the signature.

.. code-block:: bash

    pulp ansible repository update --name foo --sigstore-signing-service $SIGSTORE_SIGNING_SERVICE_HREF
    # Validate signature against Sigstore Signing Service associated with the repository
    pulp ansible content -t signature upload --signature $SIGSTORE_SIGNATURE --certificate $SIGSTORE_CERTIFICATE --bundle $SIGSTORE_BUNDLE --collection $COLLECTION_HREF --repository foo

