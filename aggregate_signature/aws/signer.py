""" """
from aggregate_signature.lib import setup, keygen, sign

from json  import loads, dumps
from flask import Flask, request



# ==================================================
# Signer class
# ==================================================
class Signer():
	# ----------------------------------------------
	# init
	# ----------------------------------------------
	def __init__(self):
		self.params = setup()
		(self.sk, self.vk) = keygen(self.params)

	# ----------------------------------------------
	# sign
	# ----------------------------------------------
	def issue_signature(self, requestData):
		print(requestData)
		m = loads(requestData)
		return sign(self.params, self.sk, m)




# ==================================================
# Webapp
# ==================================================
app = Flask(__name__)
app.signer = Signer()


# index
@app.route("/", methods=['GET', 'POST'])
def app_index():
    return dumps({"status": "OK", "message": "Hello, world!"})


# issue a signature 
@app.route("/sign", methods=["GET", "POST"])
def app_sign():
    if request.method == "POST":
        try:
        	returns = app.signer.issue_signature(request.data)
        	return dumps({"status" : "OK", "returns" : returns})
        except Exception as e:
        	return dumps({"status"  : "ERROR", "message" : e.args})
    else:
    	return dumps({"status": "ERROR", "message":"Use POST method."})



# ==================================================
# entry point
# ==================================================
if __name__ == '__main__':
    app.run(host="127.0.0.1", port="5001") 

