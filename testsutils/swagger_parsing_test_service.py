from flask import Flask, jsonify

app = Flask(__name__)


@app.route('/swagger_version_not_provided')
def swagger_version_not_provided():
    return jsonify(paths={
        '/test/should/not/be/available': {
            'get': {
                'operationId': 'get_test_should_not_be_available',
                               'responses': {
                                   200: {
                                       'description': 'successful operation'
                                   }
                               }
            }
        },
    })


@app.route('/swagger_version_not_supported')
def swagger_version_not_supported():
    return jsonify(swagger='1.0',
                   paths={
                       '/test/should/not/be/available': {
                           'get': {
                               'operationId': 'get_test_should_not_be_available',
                               'responses': {
                                   200: {
                                       'description': 'successful operation'
                                   }
                               }
                           }
                       }
                   })


@app.route('/operation_id_not_provided')
def operation_id_not_provided():
    return jsonify(swagger='2.0',
                   paths={
                       '/test/without/operationId': {
                           'get': {
                               'responses': {
                                   200: {
                                       'description': 'successful operation'
                                   }
                               }
                           }
                       }
                   })


@app.route('/test/without/operationId')
def get_test_without_operation_id():
    return 'OK'


def start_server(port):
    app.run(port=port)

if __name__ == '__main__':
    start_server(8948)
