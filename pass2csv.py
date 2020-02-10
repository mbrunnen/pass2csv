#!/usr/bin/env python3
import csv
import logging
import os
import re
from argparse import ArgumentParser

import gnupg

log = logging.getLogger(__name__)

class PassParser():
    def __init__(self):

        logging.basicConfig(level=logging.INFO)

        # Set to True to allow for alternate password csv to be created
        # See README for differences

        # A regular expression list of lines that should be excluded
        self.exclude_rows = ['^---$', '^autotype ?: ?']

    def traverse(self, path):

        for root, dirs, files in os.walk(path):
            if '.git' in dirs:
                dirs.remove('.git')
            for name in files:
                yield os.path.join(root, name)

    def getMetadata(self, raw):

        lines = raw.split('\n')

        # A list of lines to keep as  (will be joined by newline)
        fields = []
        # The extracted user field
        user = ''
        # The extracted URL field
        url = ''

        line_pat = '^\s*({field_pat})\s*:\s*(.*)$'

        # Iterate through the file again to build the return array
        for line in lines:
            # If any of the exclusion patterns match, ignore the line
            if [
                    pattern for pattern in self.exclude_rows
                    if re.search(pattern, line, re.I)
            ]:
                log.warn("Skip line %s", line)
                continue

            user_search = re.search(line_pat.format(field_pat='username|user|login'), line,
                                    re.I)
            if user_search and not user:
                user = user_search.group(2)
                # The user was matched, don't add it to fields
                continue

            url_search = re.search(line_pat.format(field_pat='url'), line, re.I)
            if url_search and not url:
                url = url_search.group(2)
                # The url was matched, don't add it to fields
                continue

            fields.append(line)

        return (user, url, '\n'.join(fields).strip())

    def parse(self, basepath, path, data):
        name = os.path.splitext(os.path.basename(path))[0]
        group = os.path.dirname(os.path.os.path.relpath(path, basepath))
        split_data = data.split('\n', maxsplit=1)
        password = split_data[0]
        fields = split_data[1] if len(split_data) > 1 else ''
        # We are using the advanced format; try extracting user and url
        user, url, fields = self.getMetadata(fields)

        parsed = {
            'folder': group,
            'favorite': 0,
            'type': 'login',
            'name': name,
            'notes': '',
            'fields': fields,
            'login_uri': url,
            'login_username': user,
            'login_password': password,
            'login_totp': ''
        }
        log.info("Parsed: %s", parsed)
        return parsed


def main(gpgbinary, use_agent, pass_path):
    """Main script entrypoint."""

    pparser = PassParser()
    gpg = gnupg.GPG(use_agent=use_agent, gpgbinary=gpgbinary)
    gpg.encoding = 'latin-1'
    csv_data = []
    for file_path in pparser.traverse(pass_path):
        if os.path.splitext(file_path)[1] == '.gpg':
            log.info("Processing %s", file_path)
            with open(file_path, 'rb') as f:
                data = str(gpg.decrypt_file(f))
                if len(data) == 0:
                    raise ValueError("The password file is empty")
                csv_data.append(pparser.parse(pass_path, file_path, data))

    with open('pass.csv', 'w', newline='') as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=csv_data[0].keys(), delimiter=',')
        writer.writeheader()
        for row in csv_data:
            writer.writerow(row)


class OptionsParser(ArgumentParser):
    """Regular ArgumentParser with the script's options."""

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.add_argument(
            'pass_path',
            metavar='path',
            type=str,
            help="Path to the PasswordStore folder to use",
        )

        self.add_argument(
            '-a',
            '--agent',
            action='store_true',
            help="Use this option to ask gpg to use it's auth agent",
            dest='use_agent',
        )

        self.add_argument(
            '-b',
            '--gpgbinary',
            type=str,
            help="Path to the gpg binary you wish to use",
            dest='gpgbinary',
            default="gpg")


if __name__ == '__main__':
    PARSER = OptionsParser()
    ARGS = PARSER.parse_args()
    main(**vars(ARGS))
