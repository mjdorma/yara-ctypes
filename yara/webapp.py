import json
import httplib
from threading import Lock

import bottle

import scan

MAX_POST_SIZE = 2**20 * 100 # 100 MB

@bottle.post("scan")
def scan(self):
    filenames = []
    data_list = []
    bytes_remaining = MAX_POST_SIZE
    for filename, field in request.files.iteritems():
        if bytes_remaining <= 0:
            bottle.abbort(httplib.REQUEST_ENTITY_TOO_LARGE, 
                    'POST was > %s bytes' % MAX_POST_SIZE)
        d = field.file.read(bytes_remaining)
        bytes_remaining -= len(data)
        filenames.append(filename)
        data_list.append(d)

    try:
        res = scanner.match_data(data_list)
        results = zip(filenames, res)
    except:
        bottle.abort(httplib.INTERNAL_SERVER_ERROR, traceback.format_exc())
    return results 
    

#self.scanner = scan.SyncScanner(**scanner_kwargs)
