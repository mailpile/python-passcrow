import os
import re
import time

from .util import pmkdir
from .secret_share import random_int


def _bytes(data, cset):
    return data if isinstance(data, bytes) else bytes(data, cset)


class FileSystemStorage:
    ROW_FN_RE = re.compile(b'^[0-9a-f]+-[0-9a-f]+-[0-9a-f]+$')

    def __init__(self, workdir, create=False):
        self.workdir = workdir if isinstance(workdir, bytes) else bytes(workdir, 'latin-1')
        if not os.path.exists(self.workdir):
            if create:
                pmkdir(self.workdir, 0o700)
            else:
                raise ValueError('No such directory: %s' % workdir)

    def _row_path(self, table, row_id, col):
        row_fn = row_id + (b'-%x' % col)
        if not self.ROW_FN_RE.match(row_fn):
            raise KeyError('Invalid row ID: %s' % str(row_id, 'latin-1'))
        return os.path.join(
            self.workdir, table, row_id[-3:], row_fn)

    def _expired(self, row_id, now):
        return (0 < int(row_id.split(b'-')[0], 16) <= now)

    def _expand_row_id(self, table, row_id):
        if b'-' in row_id:
            if not os.path.exists(self._row_path(table, row_id, 0)):
                row_id = row_id.split(b'-')[-1]
        if b'-' not in row_id:
            rpath = self._row_path(table, b'0-%s' % row_id, 0)
            suffix = b'-%s-0' % row_id
            now = time.time()
            files = [fn
                for fn in os.listdir(os.path.dirname(rpath))
                if fn.endswith(suffix) and not self._expired(fn, now)]
            if len(files) == 1:
                return files[0].rsplit(b'-', 1)[0]
            raise KeyError('Not found: %s' % str(row_id, 'latin-1'))
        return row_id

    def prepare_table(self, name, rows):
        name = _bytes(name, 'latin-1')
        tpath = os.path.join(self.workdir, name)
        if not os.path.exists(tpath):
            pmkdir(tpath, 0o700)
        for prefix in range(0, 16**3):
            pmkdir(os.path.join(tpath, b'%3.3x' % prefix), 0o700)

    def expire_table(self, table, now=None):
        table = _bytes(table, 'latin-1')
        tpath = os.path.join(self.workdir, table)
        now = now or time.time()
        if not os.path.exists(tpath):
            raise KeyError('No such table: %s' % table)
        for prefix in range(0, 16**3):
            dpath = os.path.join(tpath, b'%3.3x' % prefix)
            for fn in os.listdir(dpath):
                if b'-' not in fn:
                    continue
                if self._expired(fn, now):
                    os.remove(os.path.join(dpath, fn))

    def insert(self, table, *data, rand_max=None, row_id=None, expiration=0):
        table = _bytes(table, 'latin-1')
        if not os.path.exists(os.path.join(self.workdir, table)):
            raise KeyError('No such table: %s' % table)
        if not row_id:
            row_id = b'%3.3x' % random_int(rand_max or 2**128)
        row_id = _bytes(row_id, 'latin-1')
        row_id = b'%x-%s' % (int(expiration), row_id.split(b'-')[-1])
        for col, cdata in enumerate(data):
            cpath = self._row_path(table, row_id, col)
            with open(cpath, 'wb') as fd:
                cdata = _bytes(cdata, 'latin-1')
                fd.write(cdata)
        return str(row_id, 'latin-1')

    def delete(self, table, row_id):
        table = _bytes(table, 'latin-1')
        if not os.path.exists(os.path.join(self.workdir, table)):
            raise KeyError('No such table: %s' % table)
        try:
            row_id = self._expand_row_id(table, _bytes(row_id, 'latin-1'))
        except KeyError:
            return True
        removed = 0
        for col in range(0, 9999):
            try:
                os.remove(self._row_path(table, row_id, col))
                removed += 1
            except OSError:
                break
        return (removed > 0)

    def fetch(self, table, row_id, now=None):
        table = _bytes(table, 'latin-1')
        row_id = self._expand_row_id(table, _bytes(row_id, 'latin-1'))
        expired = self._expired(row_id, now or time.time())
        row = []
        for col in range(0, 9999):
            try:
                fn = self._row_path(table, row_id, col)
                with open(fn, 'rb') as fd:
                    if not expired:
                        row.append(fd.read())
                if expired:
                    os.remove(fn)
            except (OSError, IOError):
                break
        if not row:
            raise KeyError("Not found: %s" % str(row_id, 'latin-1'))
        return row


if __name__ == '__main__':
    import tempfile
    data_dir = tempfile.mkdtemp(suffix=b'.pctest')

    fss = FileSystemStorage(data_dir, create=True)
    fss.prepare_table('testing', ['one', 'two'])

    exp = time.time() + 300
    id1 = fss.insert('testing', 'stuff', 'things', expiration=exp)
    assert([b'stuff', b'things'] == fss.fetch('testing', id1))
    try:
        fss.fetch('testing', id1, now=exp+1) 
        assert(not 'reached')
    except KeyError:
        pass

    id2 = fss.insert('testing', 'stuff', 'things', expiration=exp)
    assert([b'stuff', b'things'] == fss.fetch('testing', id2))
    fss.expire_table('testing', now=exp+1)
    try:
        fss.fetch('testing', id1)
        assert(not 'reached')
    except KeyError:
        pass

    id3 = fss.insert('testing', 'stuff', rand_max=1000000)
    print('%s' % id3)
    assert([b'stuff'] == fss.fetch('testing', id3.split('-')[-1]))
    fss.delete('testing', id3)
    try:
        fss.fetch('testing', id3)
        assert(not 'reached')
    except KeyError:
        pass

    os.system(b'find %s -type f -ls' % data_dir)
    os.system(b'rm -rf %s' % data_dir)
    print('ok')
