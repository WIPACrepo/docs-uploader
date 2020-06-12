"""
Server for docs uploading
"""

import os
import shutil
import logging
import asyncio
import base64
from functools import wraps, partial
import random
from io import BytesIO
import tarfile

from tornado.web import RequestHandler, HTTPError, MissingArgumentError
from tornado.template import DictLoader
from rest_tools.server import RestServer, from_environment


default_config = {
    'DOCS_PATH': None,
    'HOST': 'localhost',
    'PORT': 8080,
    'DEBUG': False,
    'LOG_LEVEL': 'INFO',
    'AUTH_USERNAME': None,
    'AUTH_PASSWORD': None,
    'COOKIE_SECRET': ''.join([random.choice('0123456789abcdef') for _ in range(32)])
}

class BaseHandler(RequestHandler):
    def initialize(self, debug=False, auth_username=None, auth_password=None, docs_path=None):
        super().initialize()
        self.debug = debug
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_data = None
        self.docs_path = docs_path

    def get_current_user(self):
        if 'Authorization' in self.request.headers:
            try:
                auth_type,data = self.request.headers['Authorization'].split(' ', 1)
                if auth_type.lower() != 'basic':
                    raise Exception('bad header type')
                data_decode = base64.b64decode(data).decode()
                self.auth_data = True
                user, pwd = data_decode.split(':', 2)
                if user != self.auth_username:
                    raise Exception('bad username')
                if pwd != self.auth_password:
                    raise Exception('bad password')
                return user
            except Exception:
                if self.debug and 'Authorization' in self.request.headers:
                    logging.debug('Authorization: %r', self.request.headers['Authorization'])
                logging.info('failed auth', exc_info=True)
        return None

def authenticated(method):
    """
    Decorate methods with this to require that the Authorization
    header is filled.
    On failure, raises a 401 or 403 error.
    Raises:
        :py:class:`tornado.web.HTTPError`
    """
    @wraps(method)
    async def wrapper(self, *args, **kwargs):
        if not self.current_user:
            if self.auth_data:
                raise HTTPError(403, reason="authentication failed")
            else:
                self.set_status(401)
                self.set_header('WWW-Authenticate', 'Basic realm=Restricted')
                self.finish()
        else:
            return await method(self, *args, **kwargs)
    return wrapper

def extract(path, data):
    f = BytesIO(data)
    tf = tarfile.open(fileobj=f, mode='r:gz')
    filenames = tf.getnames()
    if any('..' in n for n in filenames):
        raise Exception('filename contains ..')
    if any(n[0] == '/' for n in filenames):
        raise Exception('filename starts with /')
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)
    for name in filenames:
        tf.extract(name, path=path, set_attrs=False)

def rebuild_index(path):
    paths = {}
    for meta in os.listdir(path):
        paths[meta] = os.listdir(os.path.join(path,meta))
    with open(os.path.join(path,'index.html'),'w') as f:
        print('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Docs</title><meta name="description" content="IceCube Documentation Repository"></head><body><h1>Docs</h1>', file=f)
        for meta in paths:
            print('<h3>'+meta+'</h3><ul>', file=f)
            for version in sorted(paths[meta], reverse=True):
                print(f'<li><a href="{meta}/{version}">{version}</a></li>', file=f)
            print('</ul>', file=f)
        print('</body></html>', file=f)

class UploadHandler(BaseHandler):
    def initialize(self, **kwargs):
        super().initialize(**kwargs)
        self.path = ''

    def get_template_namespace(self):
        namespace = super().get_template_namespace()
        namespace['error'] = False
        namespace['success'] = False
        namespace['path'] = self.path
        return namespace

    def write_error(self, status_code: 500, **kwargs):
        error = 'unknown error'
        if 'reason' in kwargs:
            error = kwargs['reason']
        self.render('upload', error=error)
        self.set_status(status_code)

    @authenticated
    async def get(self):
        self.render('upload')

    @authenticated
    async def post(self):
        self.path = self.get_argument('path', None)
        if not self.path:
            return self.send_error(400, reason='missing path')

        if 'file' in self.request.files and self.request.files['file']:
            data = self.request.files['file'][0].body
        else:
            return self.send_error(400, reason='missing file')

        logging.info(f'path={self.path}')

        # extract data
        try:
            await asyncio.get_event_loop().run_in_executor(None,
                partial(extract, os.path.join(self.docs_path, self.path), data))
        except Exception as e:
            return self.send_error(400, reason=f'cannot extract docs: {e}')

        # update index
        try:
            await asyncio.get_event_loop().run_in_executor(None,
                partial(rebuild_index, self.docs_path))
        except Exception as e:
            return self.send_error(400, reason=f'cannot update index: {e}')

        self.render('upload', success=True)

upload_template = """
<html>
<head>
<title>Docs Upload</title>
<style>
.msg_box {
    margin: 1em;
    font-size: 1.5em;
}
.error {
    color: red;
}
form div {
    margin: 1em;
}
</style>
</head>
<body>
<h2>Docs upload page</h2>
<form method="post" enctype="multipart/form-data">
{% module xsrf_form_html() %}
    <div>Path to extract in: <input type="text" id="path" name="path" value="{{ path }}" required></div>
    <div>File: <input type="file" id="file" name="file"></div>
    <div><input type="submit" value="Upload"></div>
</form>
{% if error or success %}
<div class="msg_box">
  {% if error %}<span class="error">{{ error }}</span>{% end %}
  {% if success %}Success!{% end %}
</div>
{% end %}
</body>
</html>
"""

templates = DictLoader({
    'upload': upload_template,
})

def create_server(config):
    static_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),'static')

    kwargs = {
        'debug': config['DEBUG'],
        'auth_username': config['AUTH_USERNAME'],
        'auth_password': config['AUTH_PASSWORD'],
        'docs_path': config['DOCS_PATH'],
    }

    server = RestServer(static_path=static_path, debug=config['DEBUG'],
            template_loader=templates, xsrf_cookies=True, cookie_secret=config['COOKIE_SECRET'])
    server.add_route('/upload', UploadHandler, kwargs)
    server.startup(address=config['HOST'], port=config['PORT'])

    return server

# handle logging
setlevel = {
    'CRITICAL': logging.CRITICAL, # execution cannot continue
    'FATAL': logging.CRITICAL,
    'ERROR': logging.ERROR, # something is wrong, but try to continue
    'WARNING': logging.WARNING, # non-ideal behavior, important event
    'WARN': logging.WARNING,
    'INFO': logging.INFO, # initial debug information
    'DEBUG': logging.DEBUG # the things no one wants to see
}

def main():
    config = from_environment(default_config)

    logformat='%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)s - %(message)s'
    logging.basicConfig(format=logformat, level=setlevel[config['LOG_LEVEL'].upper()])

    # start server
    create_server(config)
    asyncio.get_event_loop().run_forever()

if __name__ == '__main__':
    main()
