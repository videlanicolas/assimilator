.. _key management:

API Key Management
==================

There are two URL from where the admin logs in, one of those is the Key management.

Key management handles the API keys sent to Assimilator, it identifies API keys with a matching authorization token. When an API key is randomly generated it has no authorization to do stuff on the API, that's when authorization tokens come in. Each API key has a list of authorization tokens which contain a regex in the URL and available HTTP methods.
For example:

.. code-block:: json

   {
	   "token": 
	   [
	      {
	         "path": "/api/.*",
	         "method": 
	         [
	            "GET",
	            "POST",
	            "PUT"
	         ]
	      }
	   ],
	   "key": "BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s"
   }


Here we have an API key containing the key and token. The key is just 100 pseudo-random numbers and letters, this key should travel as an HTTP header named 'key' in the request. The other part is the token, it consists of a list where each object in that list consist of a dictionary with a 'path' and 'method'.
The 'path' is a regex applied over the requested URL, and 'method' is a list of allowed HTTP methods over that regex match. Our request should match some object on this list, the following example shows a positive authentication.

::

	GET /api/hq/rules HTTP/1.1
	key: BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s
	Content-Type: application/json

This example shows a denied authorization.

::

	DELETE /api/hq/rules HTTP/1.1
	key: BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s
	Content-Type: application/json

With this scheme one can assign API keys to both users and scripts, therefore a user can easily use this API (ie. `Postman <https://www.getpostman.com/>`_) and also a Python script (ie. with `Requests <http://docs.python-requests.org/en/master/>`_.

Add a user
----------

To add a new user to the API use the configured user and password for admin access (located `here <https://github.com/videlanicolas/assimilator/blob/master/assimilator.conf#L47>`_) as HTTP authentication. Make a GET to /keymgmt.

::

	GET /keymgmt HTTP/1.1
	Authorization: Basic YWRtaW46c2VjcmV0
	Content-Type: application/json

If you never added a user to the API this request should return an empty JSON. If not, it will return a JSON dictionary of user numbers and their respective key and tokens.

.. code-block:: json

   {
      "1" : 
      {
	     "comment" : "Audit"
	     "token": 
	     [
	        {
	           "path": "/api/.*",
	           "method": [
	              "GET",
	              "POST",
	              "PUT",
	              "PATCH",
	              "DELETE"
	           ]
	        }
	     ],
	     "key": "BDP0NyHZMDfz98kcmD3GuBIQGW9EZTgWGPf56dWnkD3LGM3dZPaZICrKVnTnQWh5YdGLh5SJ9ktg7ReR4le94zyxdigdLTHHf8s"
	  },
	  "2" :
	  {
	     "comment": "NOC",
	     "token":
	     [
	        {
	           "path": "/api/hq/.*",
	           "method": [
	              "GET"
	           ]
	        },
	        {
	           "path": "/api/branch1/.*",
	           "method": [
	              "GET"
	           ]
	        }
	     ],
	     "key": "xTYRt9tKODjh42smjmoHno3j10OD3LGM3dZgHcen1S5NhICCRzdlrj6VJJwBpBTVgXmfpI3S63bo8aBGZT1CGR91rroBvTv8cer"
      }
   }

To add a user you need to generate a new pseudo-random API key.

::

	POST /keymgmt/generate HTTP/1.1
	Authorization: Basic YWRtaW46c2VjcmV0
	Content-Type: application/json
	{"comment" : "Some User"}

::

	201 CREATED

.. code-block:: json

   {
	"3": {
		"comment": "Some User",
		"token": [],
		"key": "xWCALV3fPLqnUZ8avZaCeDGyXhTwrTSEMcf7iH7o1j6XG2gGJF75kAXk0l8b2GMsrvHELrXS1T8S4tjfN2SQB2RVH13B0gzGa0vh"
	}
   }

And now assign new tokens to that user.

::

	POST /keymgmt/3 HTTP/1.1
	Authorization: Basic YWRtaW46c2VjcmV0
	Content-Type: application/json
	{
        "path": "\/api\/hq\/rules\/.*",
        "method": [
          "GET",
          "POST"
        ]
	}

::

	201 CREATED


.. code-block:: json

   {
	"path": "/api/hq/rules/.*",
	"method": [
		"GET",
		"POST"
		]
   }

Take note of the backslash.
Check that it was successfull with GET.

::

	GET /keymgmt/3 HTTP/1.1
	Authorization: Basic YWRtaW46c2VjcmV0
	Content-Type: application/json

::

	200 OK

.. code-block:: json

   {
	"3": {
		"comment": "Some User",
		"token": [
			{
			"path": "/api/hq/rules/.*",
			"method": [
			  "GET",
			  "POST"
			]
			}],
		"key": "xWCALV3fPLqnUZ8avZaCeDGyXhTwrTSEMcf7iH7o1j6XG2gGJF75kAXk0l8b2GMsrvHELrXS1T8S4tjfN2SQB2RVH13B0gzGa0vh"
		}
   }

You can't delete specific authorizataion tokens, you would have to delete the entire API key and start over. For that one can use the DELETE method.

::

	DELETE /keymgmt/3 HTTP/1.1
	Authorization: Basic YWRtaW46c2VjcmV0
	Content-Type: application/json

::

	200 OK
