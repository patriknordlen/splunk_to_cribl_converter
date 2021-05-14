#!/usr/bin/env python3

from argparse import ArgumentParser
import logging
import glob
import re
import sys
import yaml
from collections import OrderedDict

conf = {}
logger = logging.getLogger()


def read_props(props):
    def set_sourcetype(line):
        if "::" in line and not "sourcetype::" in line:
            logger.debug(f"Unsupported stanza: {line}")
            sourcetype = None
        else:
            sourcetype = re.match(r"^\[(?:sourcetype::)?([^\]]+)\]", line).group(1)
            logger.debug(f"Applying to sourcetype {sourcetype}")
            if not sourcetype in conf.keys():
                conf[sourcetype] = {"regexes": [], "report_references": [], "lookups": [], "aliases": []}

            return sourcetype

    # TODO: handle extracts operating on other fields than _raw, i.e. ending in "in <field>"
    def add_extract(line):
        match = re.match(r"EXTRACT.+?=\s*(?P<regex>.+)", line)
        conf[sourcetype]["regexes"].append(match.group("regex").replace("\\\\", "\\"))

    def add_fieldaliases(line):
        matches = re.findall(r"(\S+) as (\S+)", line, flags=re.IGNORECASE)
        for match in matches:
            conf[sourcetype]["aliases"].append(match)

    def add_report_references(line):
        matches = re.findall(r"([\w\d_]+)[\s,]+", line, flags=re.IGNORECASE)
        for match in matches[1:]:
            conf[sourcetype]["report_references"].append(match)

    def add_lookup(line):
        if "output" in line.lower():
            match = re.match(
                r"LOOKUP.+?=\s*(?P<name>\S+)\s+(?P<src_fields>.+?)\s+OUTPUT\s+(?P<dest_fields>.+)",
                line,
                flags=re.IGNORECASE,
            )
        else:
            match = re.match(r"LOOKUP.+?=\s*(?P<name>\S+)\s+(?P<src_fields>.+)")

        conf[sourcetype]["lookups"].append(match.groupdict())

    for p in props:
        with open(p) as f:
            sourcetype = None
            for line in f:
                if line.startswith("["):
                    sourcetype = set_sourcetype(line)
                    continue

                if sourcetype:
                    if line.startswith("EXTRACT"):
                        add_extract(line)
                    elif line.startswith("FIELDALIAS"):
                        add_fieldaliases(line)
                    elif line.startswith("REPORT") or line.startswith("TRANSFORMS"):
                        add_report_references(line)
                    elif line.startswith("LOOKUP"):
                        add_lookup(line)
                    elif line.startswith("EVAL"):
                        logger.debug(f"Can't convert this EVAL statement automatically: {line}")
                    elif re.match(r"^(\s|#.+)*$", line):
                        continue
                    else:
                        logger.debug(f"Unknown statement encountered: {line}")


def read_transforms(transforms):
    def set_current_report(line):
        name = re.match(r"^\[(?P<name>[^\]]+)", line).group("name")
        return name

    def add_inline_regex(line):
        for sourcetype in conf.keys():
            if current_report in conf[sourcetype]["report_references"]:
                conf[sourcetype]["regexes"].append(match.group("regex").replace("\\\\", "\\"))

    def add_regexes_with_format(reports):
        for name, report in reports.items():
            pos = {}
            positions = re.findall(r"\s*(.+?)::\$(\d+)", report.get("format", ""))
            for p in positions:
                pos[int(p[1])] = p[0]

            i = 1
            while re.search(r"[^\\]\([^?]", report.get("regex", "")):
                field = pos[i] if i in pos else f"unused{i}"
                report["regex"] = re.sub(r"([^\\]\()([^?])", f"\\1?<{field}>\\2", report["regex"], count=1)
                i += 1

            for sourcetype in conf.keys():
                if name in conf[sourcetype]["report_references"]:
                    conf[sourcetype]["regexes"].append(report["regex"])

    def add_report_property(report, property, value):
        if report in reports:
            reports[report][property] = value
        else:
            reports[report] = {property: value}

    reports = {}
    for t in transforms:
        with open(t) as f:
            for line in f:
                if line.startswith("["):
                    current_report = set_current_report(line)
                    continue

                if line.startswith("REGEX"):
                    match = re.match(r"REGEX.+?=\s*(?P<regex>.+)", line)
                    if re.search(r"\(\?P?<", match.group("regex")):  # Inline field names
                        add_inline_regex(line)
                    else:
                        add_report_property(current_report, "regex", match.group("regex"))
                elif line.startswith("FORMAT"):
                    match = re.match(r"FORMAT.+?=\s*(?P<format>.+)", line)
                    add_report_property(current_report, "format", match.group("format"))

    add_regexes_with_format(reports)


def setup_logger(loglevel):
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(loglevel)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def find_app_confs(app):
    props = glob.glob(f"{app}/*/props.conf", recursive=True)
    transforms = glob.glob(f"{app}/*/transforms.conf", recursive=True)
    lookups = glob.glob(f"{app}/lookups/*", recursive=True)

    logger.debug(f"Found the following props files: {props}")
    logger.debug(f"Found the following transforms files: {transforms}")
    logger.debug(f"Found the following lookup files: {lookups}")

    return props, transforms, lookups


def write_cribl_conf(conf, template):
    with open(template) as f:
        t = yaml.safe_load(f)

    out = {"regexes": [], "aliases": []}
    for sourcetype in conf.keys():
        if len(conf[sourcetype].get("regexes", [])) > 0:
            re_tpl = {
                "id": "regex_extract",
                "filter": True,
                "disabled": False,
                "conf": {
                    "source": "_raw",
                    "iterations": 100,
                    "overwrite": False,
                    "regex": f"/{conf[sourcetype]['regexes'][0]}/",
                },
                "groupId": "parse",
            }
            if len(conf[sourcetype].get("regexes", [])) > 1:
                re_tpl["conf"]["regexList"] = [f"/{regex}/" for regex in conf[sourcetype]["regexes"][1:]]

            out["regexes"].append(re_tpl)

        if len(conf[sourcetype].get("aliases", [])) > 0:
            out["aliases"].append(
                {
                    "id": "eval",
                    "filter": True,
                    "disabled": False,
                    "conf": {
                        "add": [
                            {"name": dstfield, "value": srcfield} for srcfield, dstfield in conf[sourcetype]["aliases"]
                        ]
                    },
                    "groupId": "parse",
                }
            )

    t.setdefault("functions", []).append(out["regexes"])
    t.setdefault("functions", []).append(out["aliases"])
    print(yaml.safe_dump(t, sort_keys=False))


def main():
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "-t",
        "--template",
        default=f"{sys.path[0]}/template.yml",
        help="YAML template file to use for writing Cribl configuration",
    )
    parser.add_argument("-n", "--name", required=True, help="Name of the Cribl pipeline to create")
    parser.add_argument("app")
    args = parser.parse_args()

    if args.verbose:
        setup_logger(logging.DEBUG)
    else:
        setup_logger(logging.INFO)

    props, transforms, lookups = find_app_confs(args.app)

    read_props(props)
    read_transforms(transforms)

    write_cribl_conf(conf, args.template)


if __name__ == "__main__":
    main()