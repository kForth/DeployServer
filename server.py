import json
import hmac
import hashlib
import subprocess

from flask import Flask, jsonify, make_response, request, abort

app = Flask(__name__)
config = json.load(open(app.root_path + 'config.json'))


@app.route('/update_kestin', methods=['POST'])
def update_kestin():
    secret = config['kestin']['github-secret']
    digester = hmac.new(secret.encode('utf-8'), digestmod=hashlib.sha1)
    headers = dict(request.headers)
    print(dict(headers))
    if 'X-Hub-Signature' in headers.keys():
        hub_sig = str(headers['X-Hub-Signature']).encode('ascii', 'ignore')
        user_agent = str(headers['User-Agent']).encode('ascii', 'ignore')
        if request.json:
            data = request.data
            digester.update(data)
            digested = digester.hexdigest()  # Currently doesn't resolve properly
            if 'GitHub-Hookshot' in user_agent or hmac.compare_digest(digested, hub_sig.split("=")[1]):
                subprocess.Popen(config['kestin']['command'].split(" "), cwd=config['kestin']['folder-path'])
                return make_response(jsonify({'success': True}), 200, {'ContentType': 'application/json'})

    return abort(401)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5050)
