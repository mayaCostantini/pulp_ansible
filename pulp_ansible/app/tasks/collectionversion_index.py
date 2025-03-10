import logging
from semantic_version import Version

from django.db.models import Q

from pulp_ansible.app.models import (
    AnsibleDistribution,
    AnsibleCollectionDeprecated,
    AnsibleNamespaceMetadata,
    AnsibleRepository,
    CollectionVersion,
    CollectionVersionSignature,
    CrossRepositoryCollectionVersionIndex as CVIndex,
)


log = logging.getLogger(__name__)


def has_distribution(repository, repository_version):
    """Is -any- distribution attached to this repo or repo version?"""
    return AnsibleDistribution.objects.filter(
        Q(repository=repository) | Q(repository_version=repository_version)
    ).exists()


def get_highest_version_string_from_cv_objects(cv_objects):
    """Return the highest version as a string (preferring stable releases)."""
    versions_strings = [x.version for x in cv_objects]
    versions = [Version(x) for x in versions_strings]
    versions = sorted(versions, reverse=True)
    stable_versions = [x for x in versions if not x.prerelease]
    if stable_versions:
        return str(stable_versions[0])
    return str(versions[0])


def update_index(distribution=None, repository=None, repository_version=None, is_latest=False):
    """Rebuild index by distribtion|repository|repositoryversion."""

    # if the distro points at a specific repo version, we should use that in the index
    # otherwise the index value for repository version should be null
    # use_repository_version = False
    use_repository_version = not is_latest

    # a repov was passed in so we should use that
    # if repository_version:
    #    use_repository_version = True

    # make sure the distro points at a repo[version]
    if distribution and not repository and not repository_version:
        # sometimes distros point at a version
        if distribution.repository_version:
            repository = distribution.repository_version.repository
            repository_version = distribution.repository_version
            use_repository_version = True

        # sometimes distros point at a repository
        elif distribution.repository is not None:
            repository = distribution.repository
            repository_version = distribution.repository.latest_version()
            # is_latest = True
            use_repository_version = False

        # sometimes distros point at nothing?
        else:
            return

    # extract repository from repository version if needed
    if repository is None:
        repository = repository_version.repository

    # optimization: -must- have an AnsibleRepository for the index model
    if not isinstance(repository, AnsibleRepository):
        repository = AnsibleRepository.objects.filter(pk=repository.pk).first()
        if repository is None:
            return

    # optimization: we only want to index "distributed" CVs
    if distribution is None and not has_distribution(repository, repository_version):
        return

    # This block handles a case where the distribution that points at a repository
    # has been deleted. If no other distribution points at the repository, all related
    # indexes need to be removed and to exit early.
    if not use_repository_version:
        if not has_distribution(repository, repository_version):
            CVIndex.objects.filter(repository=repository, repository_version=None).delete()
            return

    # optimizaion: exit early if using a repo version and it's alreay indexed
    if use_repository_version:
        if CVIndex.objects.filter(repository_version=repository_version).exists():
            return

    # get all CVs in this repository version
    cvs = repository_version.content.filter(pulp_type="ansible.collection_version").values_list(
        "pk", flat=True
    )
    cvs = CollectionVersion.objects.filter(pk__in=cvs)

    # clean out cvs no longer in the repo when a distro w/ a repo
    if not use_repository_version:
        CVIndex.objects.filter(repository=repository, repository_version=None).exclude(
            collection_version__pk__in=cvs
        ).delete()

    # get the set of signatures in this repo version
    repo_signatures_pks = repository_version.content.filter(
        pulp_type="ansible.collection_signature"
    ).values_list("pk", flat=True)
    repo_signatures = CollectionVersionSignature.objects.filter(pk__in=repo_signatures_pks)

    # get the set of deprecations in this repo version
    deprecations = repository_version.content.filter(
        pulp_type="ansible.collection_deprecation"
    ).values_list("pk", flat=True)
    deprecations = AnsibleCollectionDeprecated.objects.filter(pk__in=deprecations)
    deprecations_set = {(x.namespace, x.name) for x in deprecations}

    # find all namespaces in the repo version
    namespaces = repository_version.get_content(content_qs=AnsibleNamespaceMetadata.objects).all()
    namespaces = {x.name: x for x in namespaces}

    # map out the namespace(s).name(s) for everything in the repo version
    colset = set(cvs.values_list("namespace", "name").distinct())

    repo_v = None
    if use_repository_version:
        repo_v = repository_version

    # iterate through each collection in the repository
    for colkey in colset:
        namespace, name = colkey

        # get all the versions for this collection
        related_cvs = cvs.filter(namespace=namespace, name=name).only("version")

        # what is the "highest" version in this list?
        highest_version = get_highest_version_string_from_cv_objects(related_cvs)

        # should all of these CVs be deprecated?
        is_deprecated = colkey in deprecations_set

        # process each related CV
        for rcv in related_cvs:
            # get the related signatures for this CV
            rcv_signatures = repo_signatures.filter(signed_collection=rcv).count()

            # create|update the index for this CV
            CVIndex.objects.update_or_create(
                repository=repository,
                repository_version=repo_v,
                collection_version=rcv,
                defaults={
                    "is_highest": rcv.version == highest_version,
                    "is_signed": rcv_signatures > 0,
                    "is_deprecated": is_deprecated,
                    "namespace_metadata": namespaces.get(namespace, None),
                },
            )


def update_distribution_index(distribution):
    return update_index(distribution=distribution)


def rebuild_index():
    """Rebuild -everything-."""
    indexed_repos = set()
    dqs = AnsibleDistribution.objects.select_related(
        "repository", "repository_version", "repository_version__repository"
    ).all()
    for distro in dqs:
        if distro.repository_version:
            rv = distro.repository_version
        else:
            rv = distro.repository.latest_version()

        if rv.pk in indexed_repos:
            continue

        update_index(distribution=distro)
        indexed_repos.add(rv.pk)
