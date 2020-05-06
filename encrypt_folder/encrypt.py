import base64
import hashlib
import os
import random
import string
import zipfile
from getpass import getpass

import click
from cryptography.fernet import Fernet


class Zip(object):
    DIRNAME_FILE = ".5385362185458785436-origin-dirname"

    @classmethod
    def zip(cls, dirname, zip_filename):
        with open(os.path.join(dirname, cls.DIRNAME_FILE), "w") as f:
            f.write(os.path.split(dirname)[-1])

        with zipfile.ZipFile(zip_filename, "w") as zip_file:
            for file in cls._retrieve_files(dirname):
                zip_file.write(file, arcname=file[len(dirname) :])

        os.unlink(os.path.join(dirname, cls.DIRNAME_FILE))

    @classmethod
    def unzip(cls, zip_filename, dirname):
        if os.path.exists(os.path.abspath(dirname)):
            raise ValueError("dir '%s' exists" % dirname)

        with zipfile.ZipFile(zip_filename, "r") as zip_file:
            for name in zip_file.namelist():
                cls._ensure_dir(os.path.join(dirname, name))
                with open(os.path.join(dirname, name), "wb") as fw:
                    fw.write(zip_file.read(name))

    @classmethod
    def _ensure_dir(cls, filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)

    @classmethod
    def _retrieve_files(cls, dirname):
        paths = []
        for root, _, files in os.walk(dirname):
            for filename in files:
                paths.append(os.path.join(root, filename))

        return paths


class EncryptFolder(object):
    SALT = "5385384761080623059"

    CURRENT_USER_HOME = os.path.expanduser("~")

    def __init__(self, encrypt, source):
        self.encrypt = encrypt
        self.source = os.path.abspath(source).rstrip("/")

    def run(self):
        self._check_args()
        return self._encrypt() if self.encrypt else self._decrypt()

    def _check_args(self):
        if self.encrypt:
            if not os.path.isdir(self.source):
                raise ValueError("bad encrypt source: %s" % self.source)
        else:
            if not os.path.isfile(self.source):
                raise ValueError("bad decrypt source: %s" % self.source)

    def _encrypt(self):
        work_dir = os.path.dirname(os.path.abspath(self.source))

        zip_filename = "%s/.%s.zip" % (work_dir, self._generate_filename())
        Zip.zip(self.source, zip_filename)

        encrypted_filename = "%s/%s.e" % (work_dir, self._generate_filename())
        with open(zip_filename, "rb") as fr:
            with open(encrypted_filename, "wb") as fw:
                fw.write(Fernet(self._key(self._pwd())).encrypt(fr.read()))

        os.unlink(zip_filename)

    def _decrypt(self):
        work_dir = os.path.dirname(os.path.abspath(self.source))

        zip_filename = "%s/.%s.zip" % (
            work_dir,
            os.path.splitext(os.path.split(self.source)[-1])[0],
        )
        with open(self.source, "rb") as fr:
            with open(zip_filename, "wb") as fw:
                fw.write(Fernet(self._key(self._pwd())).decrypt(fr.read()))

        tmp_dir = "%s/.%s" % (
            work_dir,
            os.path.splitext(os.path.split(self.source)[-1])[0],
        )
        Zip.unzip(zip_filename, tmp_dir)

        target = os.path.join(
            work_dir,
            self._read_as_string(os.path.join(tmp_dir, Zip.DIRNAME_FILE)).strip(),
        )
        os.rename(tmp_dir, target)
        os.unlink(os.path.join(target, Zip.DIRNAME_FILE))

    def _pwd(self):
        return getpass("Please input password: ")

    def _key(self, pwd):
        return base64.b64encode(
            hashlib.pbkdf2_hmac(
                "sha256", pwd.encode("utf8"), self.SALT.encode("utf8"), 100000
            )
        )

    def _generate_filename(self):
        return "".join(random.choice(string.ascii_letters) for _ in range(12))

    def _read_as_string(self, filename):
        with open(filename, "r", encoding="utf8") as f:
            return f.read()


@click.command()
@click.option("--encrypt/--decrypt", default=True)
@click.argument("source")
def start(encrypt, source):
    EncryptFolder(encrypt, source).run()
