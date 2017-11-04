import hashlib
import hmac
import json
import subprocess

from flask import Flask, abort, jsonify, make_response, request


def add_url_rule(route, func, methods=('POST',), url_prefix=""):
    app.add_url_rule(url_prefix + route, route, view_func=func, methods=methods)


def handle_site_update_request(site_key):
    secret = config[site_key]['github-secret']
    headers = dict(request.headers)
    if 'X-Hub-Signature' in headers.keys() and request.json:
        hub_sig = str(headers['X-Hub-Signature'])
        github_verified = verify_github_signature(secret, request.data, hub_sig)
        user_agent = str(headers['User-Agent'])
        print(user_agent)
        if 'GitHub-Hookshot' in user_agent or github_verified:
            command = config[site_key]['command']
            if type(command) is not list:
                command = [command]
            for cmd in command:
                subprocess.Popen(cmd.split(" "), cwd=config[site_key]['folder-path']).wait()
            return make_response(jsonify({'success': True}), 200, {'ContentType': 'application/json'})
    return abort(400)


def verify_github_signature(key, payload, signature):
    digester = hmac.new(key.encode('utf-8'), digestmod=hashlib.sha1)
    digester.update(payload)
    digested = digester.hexdigest()  # Currently doesn't resolve properly or something
    return hmac.compare_digest(digested, str(signature).split('=')[1])


app = Flask(__name__)
config = json.load(open(app.root_path + '/config.json'))

add_url_rule('/update_kestin', lambda: handle_site_update_request('kestin'))
add_url_rule('/update_clooney', lambda: handle_site_update_request('clooney'))
add_url_rule('/update_deploy', lambda: handle_site_update_request('deploy'))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5050)
