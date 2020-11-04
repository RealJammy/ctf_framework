# CTF framework
## By EuanB26

Some documentation will be written sometime soon to see how this all works and where everything is.

However, if you want to get this set up locally, please follow these steps:
```bash
$ git clone https://github.com/EuanB26/ctf_framework.git
$ export FLASK_APP=ctf_framework.py
$ export ADMIN_NAME="euanb26"
$ export ADMIN_EMAIL="euanb26@gmail.com"
$ export ADMIN_PWD="testing123"
$ cd ctf_framework
$ python3 -m pip install -r requirements.txt
$ flask run --port=5000 --host=127.0.0.1
```
And then navigate to `http://127.0.0.1` on your browser, and enjoy!
