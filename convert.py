from argparse import ArgumentParser
import glob
import re

conf = {}

def read_props(props):
    def set_sourcetype(line):
        if "::" in line and not "sourcetype::" in line:
            print(f"Unsupported stanza: {line}")
            sourcetype = None
        else:
            sourcetype = re.match(r"^\[(?:sourcetype::)?([^\]]+)\]", line).group(1)
            print(f"Applying to sourcetype {sourcetype}")
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
            match = re.match(r"LOOKUP.+?=\s*(?P<name>\S+)\s+(?P<src_fields>.+?)\s+OUTPUT\s+(?P<dest_fields>.+)", line, flags=re.IGNORECASE)
        else:
            match = re.match(r"LOOKUP.+?=\s*(?P<name>\S+)\s+(?P<src_fields>.+)")

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
                    elif line.startswith("REPORT"):
                        add_report_references(line)
                    elif line.startswith("LOOKUP"):
                        add_lookup(line)
                    elif line.startswith("EVAL"):
                        print(f"Can't convert this EVAL statement automatically: {line}")
                    elif re.match(r"^(\s|#.+)*$", line):
                        continue
                    else:
                        print(f"Unknown statement encountered: {line}")


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
                        reports[current_report] = {"regex": match.group("regex")}
                elif line.startswith("FORMAT"):
                    match = re.match(r"FORMAT.+?=\s*(?P<format>.+)", line)
                    reports[current_report]["format"] = match.group("format")

    add_regexes_with_format(reports)


def main():
    parser = ArgumentParser()
    parser.add_argument("app")
    args = parser.parse_args()

    props = glob.glob(f"{args.app}/*/props.conf", recursive=True)
    transforms = glob.glob(f"{args.app}/*/transforms.conf", recursive=True)
    lookups = glob.glob(f"{args.app}/lookups/*", recursive=True)

    print(f"Found the following props files: {props}")
    print(f"Found the following transforms files: {transforms}")

    read_props(props)
    read_transforms(transforms)

    for sourcetype in conf.keys():
        print(f"{sourcetype}\n--------------------------")
        print("Regexes:")
        for regex in conf[sourcetype]["regexes"]:
            print(regex)

        print("\nAliases:")
        for srcfield, aliasfield in conf[sourcetype]["aliases"]:
            print(f"{srcfield} as {aliasfield}")

    



if __name__ == "__main__":
    main()