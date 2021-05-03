from flask import *
from flaskrund import main
app = Flask(__name__, template_folder='templates')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/success', methods=['POST'])
def success():
    if request.method == 'POST':
        f = request.files['file']
        f.save(f.filename)
        main(f.filename)
        return render_template('YOURFILE.html')


if __name__ == '__main__':
    app.run(threaded=True, port=5000)
