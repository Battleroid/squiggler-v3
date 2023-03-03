import argparse
import json
import logging
import logging.config
import os
import re
import time
import warnings
from pathlib import Path

import cerberus
import requests
import structlog
from elasticsearch import Elasticsearch
from ruamel.yaml import YAML

# I do not care, just shut up, do not break my logging
warnings.filterwarnings("ignore")

logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {"default": {"format": "%(message)s"}},
        "handlers": {
            "null": {"class": "logging.NullHandler"},
            "default": {"class": "logging.StreamHandler", "formatter": "default"},
        },
        "loggers": {
            "elasticsearch": {"handlers": ["null"], "propagate": False},
            "": {"handlers": ["default"], "level": logging.INFO},
        },
    }
)


structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(sort_keys=True),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

log = structlog.wrap_logger(logging.getLogger("squiggler"))


KB_HEALTH = "/api/task_manager/_health"
KB_FIND = "/api/saved_objects/_find"
KB_BULK_CREATE = "/api/saved_objects/_bulk_create"
KB_HEADERS = {"kbn-xsrf": "squiggler"}


def parse_config(config):
    """
    Parse and validate config.
    """

    data = YAML(typ="safe").load(os.path.expandvars(Path(config).read_bytes()))
    schema = {
        "elasticsearch": {
            "type": "dict",
            "schema": {
                "url": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": True,
        },
        "kibana": {
            "type": "dict",
            "schema": {
                "url": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": True,
        },
        "index": {
            "type": "dict",
            "schema": {
                "origin": {
                    "type": "string",
                    "allowed": ["ilm", "data stream"],
                    "required": True,
                },
                "cluster_prefix": {"type": "string", "default": "{cluster}"},
                "template": {"type": "string", "default": "{name}-*"},
                "ignore_prefix": {
                    "type": "list",
                    "schema": {"type": "string"},
                    "default": ["."],
                },
                "ignore_regex": {
                    "type": "list",
                    "schema": {"type": "string"},
                    "default": [],
                },
            },
            "required": True,
        },
        "slack": {
            "type": "dict",
            "schema": {
                "webhook": {"type": "string"},
                "message": {"type": "string", "default": "New patterns created:"},
            },
            "required": False,
        },
    }

    v = cerberus.Validator(schema)
    if not v.validate(data):
        log.error(f"Could not validate config: {v.errors}")
        raise SystemExit()
    validated_config = v.document.copy()

    return validated_config


def get_current_kibana_patterns(kb_url, kb_auth):
    """
    Pull existing list of patterns from Kibana.
    """
    rv = requests.get(
        f"{kb_url}{KB_FIND}",
        auth=kb_auth,
        params={"type": "index-pattern", "per_page": 10000},
        headers=KB_HEADERS,
    )
    patterns = set()
    total_patterns = len(rv.json()["saved_objects"])
    for pattern in rv.json()["saved_objects"]:
        if pattern["id"] not in patterns:
            patterns.add(pattern["id"])
        if pattern["attributes"]["title"] not in patterns:
            patterns.add(pattern["attributes"]["title"])
    return total_patterns, patterns


def get_ilm_patterns(es):
    """
    Get all write index ILM patterns.
    """
    patterns = set()
    current_aliases = es.indices.get_alias(
        index="*", filter_path=["**.is_write_index"]
    ).items()
    for _, alias_data in current_aliases:
        name = next(iter(alias_data["aliases"].keys()))
        if alias_data["aliases"][name]["is_write_index"] == True:
            patterns.add(name)
    return patterns


def get_data_stream_patterns(es):
    """
    Get all current data stream alias patterns.
    """
    patterns = set()
    current_streams = es.indices.get_data_stream(name="*", filter_path=["*.name"])
    if not current_streams:
        return patterns
    for stream in current_streams["data_streams"]:
        patterns.add(stream["name"])
    return patterns


def main(args):
    # Setup
    config = parse_config(args.CONFIG)
    for_real = args.for_real
    verbose = args.verbose
    if args.dump_config:
        print(json.dumps(config, indent=2, sort_keys=True))
        return

    if for_real:
        log.info("for real, not a dry run")

    # Setup cluster/kibana
    es_auth = (config["elasticsearch"]["username"], config["elasticsearch"]["password"])
    kb_auth = (config["kibana"]["username"], config["kibana"]["password"])
    kb_url = config["kibana"]["url"].rstrip("/")

    # Quick health checks
    es = Elasticsearch(hosts=config["elasticsearch"]["url"], basic_auth=es_auth)
    if not es.ping():
        raise SystemExit("Could not contact elasticsearch!")
    kb = requests.get(f"{kb_url}{KB_HEALTH}", auth=kb_auth, headers=KB_HEADERS)
    if kb.json()["status"] != "OK":
        raise SystemExit(f'Kibana not ok! Returned {kb.json()["status"]}')

    cluster_name = es.cluster.health()["cluster_name"]
    log.info("es and kibana look ok")

    # Setup ignores
    ignore_prefixes = set(config["index"]["ignore_prefix"])
    ignore_regexes = set([re.compile(p) for p in config["index"]["ignore_regex"]])
    log.debug(
        f"setup ignores",
        ignore_prefixes=",".join(ignore_prefixes),
        ignore_regexes=",".join(ignore_regexes),
    )

    # Get index patterns from kibana up front
    # current_kibana_patterns = get_current_patterns(kb_url, kb_auth)
    kibana_total_patterns, kibana_patterns = get_current_kibana_patterns(
        kb_url, kb_auth
    )
    if kibana_total_patterns >= 10000:
        log.warning(
            f"Too many kibana patterns (exceeds >10000), cannot create anymore!"
        )
        raise SystemExit()
    log.info(f"found {kibana_total_patterns} kibana patterns")

    # Get relevant patterns from elasticsearch via selected method
    current_elasticsearch_patterns = set()
    if config["index"]["origin"] == "ilm":
        log.debug("using ilm origin method")
        current_elasticsearch_patterns = get_ilm_patterns(es)

    if config["index"]["origin"] == "data stream":
        log.debug("using data stream origin method")
        current_elasticsearch_patterns = get_data_stream_patterns(es)

    # Filter set with ignores
    filtered_prefixes = set()
    if ignore_prefixes:
        for pattern in current_elasticsearch_patterns:
            if any([pattern.startswith(i) for i in ignore_prefixes]):
                filtered_prefixes.add(pattern)
                log.debug(f"Removed by prefix: {pattern}")

    filtered_regexes = set()
    if ignore_regexes:
        for pattern in filtered_prefixes:
            if any([r.search(pattern) for r in ignore_regexes]):
                filtered_regexes.add(pattern)
                log.debug(f"Removed by regex: {pattern}")

    log.debug(f"removed {len(filtered_prefixes)} patterns by prefix")
    log.debug(f"removed {len(filtered_regexes)} patterns by regex")
    filtered_patterns = current_elasticsearch_patterns - (
        filtered_prefixes | filtered_regexes
    )
    filtered_diff = len(current_elasticsearch_patterns) - len(filtered_patterns)
    if filtered_diff > 0:
        log.debug(
            f"{len(current_elasticsearch_patterns)} es patterns - {len(filtered_patterns)} filtered patterns = {filtered_diff} removed"
        )
        log.info(f"{len(filtered_patterns)} patterns after filters")
    else:
        log.info("nothing filtered out; no matches on ignores")

    # No longer required
    del current_elasticsearch_patterns
    del filtered_prefixes
    del filtered_regexes

    # Format patterns as they would end up in Kibana before comparison
    finalized_patterns = set()
    index_template = config["index"]["template"]
    final_prefix = config["index"]["cluster_prefix"] or cluster_name
    if "{cluster}" in final_prefix:
        final_prefix = final_prefix.format(cluster=cluster_name)
    for pattern in filtered_patterns:
        finalized_patterns.add(f"{final_prefix}:{index_template.format(name=pattern)}")

    # Diff the two, create only those missing
    finalized_filtered_patterns = finalized_patterns - kibana_patterns
    if verbose:
        already_exist = finalized_patterns & kibana_patterns
        for pattern in already_exist:
            log.debug(f"{pattern} already exists as an id or title, removing")
        del already_exist
    for pattern in finalized_filtered_patterns:
        log.debug(f"would create {pattern}")

    # Memory heavy object!
    del kibana_patterns

    # No patterns to create
    if not finalized_filtered_patterns:
        log.info("no patterns to create; all patterns exist between the two!")
        raise SystemExit()

    # If we're about to go over, cut it off so we don't break anything
    if (kibana_total_patterns + len(finalized_filtered_patterns)) > 10000:
        cull_mark = abs(
            10000 - (kibana_total_patterns - len(finalized_filtered_patterns))
        )
        cull_total = len(finalized_filtered_patterns) - cull_mark
        finalized_filtered_patterns = set(
            sorted(finalized_filtered_patterns)[:-cull_mark]
        )
        log.warning("squiggler needs to add more than the 10000 pattern limit!")
        log.warning(
            f"culling to be added patterns, reducing patterns from {len(finalized_filtered_patterns)} by {cull_mark} to {cull_total}"
        )

    # Piece these into 50 pattern chunks, and wait a bit between
    # nothing in the Kibana API suggests there is a max, but I don't
    # think it'll like being assaulted with 200+ patterns
    pattern_chunks = [
        sorted(finalized_filtered_patterns)[x : x + 50]
        for x in range(0, len(finalized_filtered_patterns), 50)
    ]
    errored_objects = set()
    for batch_no, chunk in enumerate(pattern_chunks, 1):
        batch = []
        for pattern in chunk:
            # Set ID and pattern, so we don't have to figure out how to
            # find the patterns that errored out
            batch.append(
                {
                    "type": "index-pattern",
                    "id": pattern,
                    "attributes": {"title": pattern, "timeFieldName": "@timestamp"},
                }
            )

        # Create the objects, then return the ones that errored (presumably because they exist)
        log.debug(f"batch {batch_no} has {len(batch)} items within it")
        log.debug(f"batch {batch_no}", batch_items=batch)
        if for_real and len(batch) > 0:
            returned_patterns = requests.post(
                f"{kb_url}{KB_BULK_CREATE}",
                json=batch,
                auth=kb_auth,
                headers=KB_HEADERS,
            ).json()

            for obj in returned_patterns["saved_objects"]:
                if "error" in obj:
                    log.debug(f"object errored on bulk create", object=obj)
                    errored_objects.add(obj["id"])

            # Give the API some rest, lol
            time.sleep(2)

    created_patterns = finalized_filtered_patterns - errored_objects
    if len(errored_objects) > 0:
        log.warning(
            f"failed to create {len(errored_objects)} patterns (they may already exist)"
        )
    log.info(f"created {len(created_patterns)} total patterns")

    # Notify, if slack info provided
    discover_template = (
        f"<{kb_url}/app/kibana#/discover?_a=(index:'{{index}}')|{{name}}>"
    )
    if config["slack"] and len(created_patterns) > 0:
        preamble = config["slack"]["message"].strip()
        urls = set()
        for pattern in sorted(created_patterns):
            urls.add(discover_template.format(index=pattern, name=pattern))
        full_message = f'{preamble} {", ".join(sorted(urls))}'
        log.debug(f"slack message would read as: {full_message}")
        if for_real:
            requests.post(
                config["slack"]["webhook"], json={"text": full_message}, timeout=30
            )
            log.info(f"sent message to slack")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("CONFIG")
    parser.add_argument("--for-real", default=False, action="store_true")
    parser.add_argument("--verbose", default=False, action="store_true")
    parser.add_argument(
        "--dump-config", default=False, action="store_true", help="Dump config and exit"
    )
    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
    try:
        main(args)
    except Exception as exc:
        log.exception("something broke!")
