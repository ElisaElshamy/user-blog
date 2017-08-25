# About

The Multi-User Blog allows users to create accounts and post blog 
entries.  Users may comment and like other users posts.  The blog 
is built using Google App Engine and the Google Datastore.

# Install

The blog is available online at:
https://udacity-user-blog-172201.appspot.com/blog

If you'd rather run the blog locally, in the blog directory type
the following command in the terminal:
```
dev_appserver.py app.yaml
```

Then go to your browser and visit http://localhost:8080/blog
The blog will be empty, you must create a user and content.
You can visit the local datastore at http://localhost:8000/datastore
in your browser.

# How to use

Create an account by visiting:
https://udacity-user-blog-172201.appspot.com/signup

Email address is optional.  Information saved on this site is only
for the purpose of keeping record of users and their activity.

https://udacity-user-blog-172201.appspot.com/welcome is where
the dashboard is located.  Visit this URL to admin your posts
and comments.

# Development

Multi-User Blog is built using the Google App Engine, the Google
Datastore and Python.  Page templates were built using Jinja 2.

## Libraries

- **Python 2.7.12**
- **Google App Engine** - https://cloud.google.com/appengine/
- **Jinja 2.9** - http://jinja.pocoo.org/docs/2.9/