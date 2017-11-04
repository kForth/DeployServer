import hashlib
import hmac
import json
import subprocess

from flask import Flask, abort, jsonify, make_response, request


def add_url_rule(route, func, methods=('POST',), url_prefix=""):
    app.add_url_rule(url_prefix + route, route, view_func=func, methods=methods)


def handle_site_update_request(key):
    conf = config[key]
    headers = dict(request.headers)
    if request.json:
        if False and 'github-secret' in conf.keys() and conf['github-secret']:  # This doesn't work right now so don't bother.
            hub_sig = str(headers['X-Hub-Signature'])
            verified = verify_github_signature(conf['github-secret'], request.data, hub_sig)
        else:
            user_agent = str(headers['User-Agent'])
            verified = 'GitHub-Hookshot' in user_agent

        if verified:
            command = conf['command']
            if type(command) is not list:
                command = [command]
            for cmd in command:
                subprocess.Popen(cmd.split(" "), cwd=conf['folder-path']).wait()
            return make_response(jsonify({'success': True}), 200, {'ContentType': 'application/json'})
    return abort(400)


def verify_github_signature(key, payload, signature):
    digester = hmac.new(key.encode('utf-8'), digestmod=hashlib.sha1)
    digester.update(payload)
    digested = digester.hexdigest()  # Currently doesn't resolve properly or something
    return hmac.compare_digest(digested, str(signature).split('=')[1])


app = Flask(__name__)
config = json.load(open(app.root_path + '/config.json'))

for site_key in config.keys():
    add_url_rule('/update_{}'.format(site_key), lambda: handle_site_update_request(site_key))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5050)
